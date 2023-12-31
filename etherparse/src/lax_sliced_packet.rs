use crate::{err::Layer, *};

/// Packet slice split into multiple slices containing
/// the different headers & payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaxSlicedPacket<'a> {
    /// Parsed part of the packet.
    pub packet: SlicedPacket<'a>,

    /// Last successfully parsed layer.
    pub last_parsed_layer: Layer,

    /// Error that stopped the parsing and the layer on which the stop occured.
    pub stop_err: Option<(err::packet::SliceError, Layer)>,
}

impl<'a> LaxSlicedPacket<'a> {
    pub fn from_ethernet(data: &'a [u8]) -> Result<LaxSlicedPacket, err::packet::EthSliceError> {
        todo!()
        //SlicedPacketCursor::new(data).slice_ethernet2()
    }
}
