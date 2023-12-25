use crate::{*, err::{LenSource, Layer, packet::SliceError}, link::ether_payload_slice::EtherPayloadSlice};

pub(crate) enum ExpectedIpProto {
    Ipv4,
    Ipv6,
}

/// Helper class for laxly slicing packets.
pub(crate) struct LaxSlicedPacketCursor<'a> {
    pub slice: &'a [u8],
    pub offset: usize,
    pub len_source: LenSource,
    pub result: LaxSlicedPacket<'a>,
}

impl<'a> LaxSlicedPacketCursor<'a> {
    pub fn new(slice: &'a [u8]) -> LaxSlicedPacketCursor<'a> {
        LaxSlicedPacketCursor {
            slice,
            offset: 0,
            len_source: LenSource::Slice,
            result: LaxSlicedPacket{
                packet: SlicedPacket {
                    link: None,
                    vlan: None,
                    ip: None,
                    transport: None,
                    payload: PayloadSlice::Icmpv4(&[]),
                },
                last_parsed_layer: Layer::Ethernet2Header,
                stop_err: None,
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

    pub fn slice_ethernet2(mut self) -> Result<LaxSlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use LinkSlice::*;

        let result = Ethernet2HeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        // cache the ether_type for later
        let ether_type = result.ether_type();

        // set the new data
        self.move_by_slice(result.slice());
        self.result.last_parsed_layer = Layer::Ethernet2Header;
        self.result.packet.link = Some(Ethernet2(result));

        // continue parsing (if required)
        match ether_type {
            IPV4 => Ok(self.slice_ip(Some(ExpectedIpProto::Ipv4))),
            IPV6 => Ok(self.slice_ip(Some(ExpectedIpProto::Ipv6))),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => Ok(self.slice_vlan(ether_type)),
            ether_type => {
                self.result.packet.payload = PayloadSlice::Ether(EtherPayloadSlice{
                    ether_type,
                    payload: self.slice,
                });
                Ok(self.result)
            },
        }
    }

    pub fn slice_vlan(mut self, ether_type: EtherType) -> LaxSlicedPacket<'a> {
        use ether_type::*;
        use VlanSlice::*;

        // cache the starting slice so the later combining
        // of outer & inner vlan is defined behavior (for miri)
        let outer_start_slice = self.slice;
        let outer = match SingleVlanHeaderSlice::from_slice(self.slice) {
            Ok(v) => v,
            Err(err) => {
                self.result.packet.payload = PayloadSlice::Ether(EtherPayloadSlice{
                    ether_type,
                    payload: self.slice,
                });
                self.result.stop_err = Some((SliceError::Len(err.add_offset(self.offset)), Layer::VlanHeader));
                return self.result;
            }
        };
        self.result.packet.vlan = Some(VlanSlice::SingleVlan(outer.clone()));
        self.move_by_slice(outer.slice());

        //check if it is a double vlan header
        match outer.ether_type() {
            //in case of a double vlan header continue with the inner
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                
                let inner = match SingleVlanHeaderSlice::from_slice(self.slice) {
                    Ok(v) => v,
                    Err(err) => {
                        self.result.packet.payload = PayloadSlice::Ether(EtherPayloadSlice {
                            ether_type: outer.ether_type(),
                            payload: self.slice
                        });
                        self.result.stop_err = Some((SliceError::Len(err.add_offset(self.offset)), Layer::VlanHeader));
                        return self.result;
                    }
                };
                self.move_by_slice(inner.slice());

                let inner_ether_type = inner.ether_type();
                self.result.packet.vlan = Some(DoubleVlan(DoubleVlanHeaderSlice {
                    // SAFETY: Safe as the lenght of the slice was previously verified.
                    slice: unsafe {
                        core::slice::from_raw_parts(
                            outer_start_slice.as_ptr(),
                            outer.slice().len() + inner.slice().len(),
                        )
                    },
                }));

                match inner_ether_type {
                    IPV4 => self.slice_ip(Some(ExpectedIpProto::Ipv4)),
                    IPV6 => self.slice_ip(Some(ExpectedIpProto::Ipv6)),
                    ether_type => {
                        self.result.packet.payload = PayloadSlice::Ether(EtherPayloadSlice{
                            ether_type,
                            payload: self.slice,
                        });
                        self.result
                    },
                }
            }
            value => {
                match value {
                    IPV4 => self.slice_ip(Some(ExpectedIpProto::Ipv4)),
                    IPV6 => self.slice_ip(Some(ExpectedIpProto::Ipv6)),
                    ether_type => {
                        self.result.packet.payload = PayloadSlice::Ether(EtherPayloadSlice{
                            ether_type,
                            payload: self.slice,
                        });
                        self.result
                    },
                }
            }
        }
    }

    pub fn slice_ip(mut self, expected_type: Option<ExpectedIpProto>) -> LaxSlicedPacket<'a> {
        todo!()
    }

}
