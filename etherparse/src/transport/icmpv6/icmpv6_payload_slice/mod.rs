mod neighbor_advertisement_payload_slice;
pub use neighbor_advertisement_payload_slice::*;

mod neighbor_solicitation_payload_slice;
pub use neighbor_solicitation_payload_slice::*;

mod redirect_payload_slice;
pub use redirect_payload_slice::*;

mod router_advertisement_payload_slice;
pub use router_advertisement_payload_slice::*;

mod router_solicitation_payload_slice;
pub use router_solicitation_payload_slice::*;

use crate::{err, icmpv6::Icmpv6Payload};

/// Borrowed, structured payload data that follows the first 8 bytes of an ICMPv6 packet.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Icmpv6PayloadSlice<'a> {
    /// Payload of a Router Solicitation message.
    RouterSolicitation(RouterSolicitationPayloadSlice<'a>),
    /// Payload of a Router Advertisement message.
    RouterAdvertisement(RouterAdvertisementPayloadSlice<'a>),
    /// Payload of a Neighbor Solicitation message.
    NeighborSolicitation(NeighborSolicitationPayloadSlice<'a>),
    /// Payload of a Neighbor Advertisement message.
    NeighborAdvertisement(NeighborAdvertisementPayloadSlice<'a>),
    /// Payload of a Redirect message.
    Redirect(RedirectPayloadSlice<'a>),
    /// Raw payload of an unsupported or currently unmodeled ICMPv6 message.
    Raw(&'a [u8]),
}

impl<'a> Icmpv6PayloadSlice<'a> {
    /// Decode a structured payload based on the ICMPv6 type.
    pub fn from_slice(
        icmp_type: &crate::Icmpv6Type,
        payload: &'a [u8],
    ) -> Result<Icmpv6PayloadSlice<'a>, err::LenError> {
        use crate::Icmpv6Type::*;

        Ok(match icmp_type {
            RouterSolicitation => Icmpv6PayloadSlice::RouterSolicitation(
                RouterSolicitationPayloadSlice::from_slice(payload)?,
            ),
            RouterAdvertisement(_) => Icmpv6PayloadSlice::RouterAdvertisement(
                RouterAdvertisementPayloadSlice::from_slice(payload)?,
            ),
            NeighborSolicitation => Icmpv6PayloadSlice::NeighborSolicitation(
                NeighborSolicitationPayloadSlice::from_slice(payload)?,
            ),
            NeighborAdvertisement(_) => Icmpv6PayloadSlice::NeighborAdvertisement(
                NeighborAdvertisementPayloadSlice::from_slice(payload)?,
            ),
            Redirect => Icmpv6PayloadSlice::Redirect(RedirectPayloadSlice::from_slice(payload)?),
            _ => Icmpv6PayloadSlice::Raw(payload),
        })
    }

    pub(crate) fn from_type_u8(
        type_u8: u8,
        code_u8: u8,
        payload: &'a [u8],
    ) -> Result<Icmpv6PayloadSlice<'a>, err::LenError> {
        use crate::icmpv6::*;

        // For the currently modeled ND message payloads (RS/RA/NS/NA/Redirect),
        // RFC 4861 validation rules require code 0 (quote: "- ICMP Code is 0.").
        // See sections 6.1.1, 6.1.2, 7.1.1, 7.1.2, and 8.1.
        if 0 != code_u8 {
            return Ok(Icmpv6PayloadSlice::Raw(payload));
        }

        match type_u8 {
            TYPE_ROUTER_SOLICITATION => Ok(Icmpv6PayloadSlice::RouterSolicitation(
                RouterSolicitationPayloadSlice::from_slice(payload)?,
            )),
            TYPE_ROUTER_ADVERTISEMENT => Ok(Icmpv6PayloadSlice::RouterAdvertisement(
                RouterAdvertisementPayloadSlice::from_slice(payload)?,
            )),
            TYPE_NEIGHBOR_SOLICITATION => Ok(Icmpv6PayloadSlice::NeighborSolicitation(
                NeighborSolicitationPayloadSlice::from_slice(payload)?,
            )),
            TYPE_NEIGHBOR_ADVERTISEMENT => Ok(Icmpv6PayloadSlice::NeighborAdvertisement(
                NeighborAdvertisementPayloadSlice::from_slice(payload)?,
            )),
            TYPE_REDIRECT_MESSAGE => Ok(Icmpv6PayloadSlice::Redirect(
                RedirectPayloadSlice::from_slice(payload)?,
            )),
            _ => Ok(Icmpv6PayloadSlice::Raw(payload)),
        }
    }

    /// Returns the full borrowed payload bytes.
    pub fn slice(&self) -> &'a [u8] {
        match self {
            Icmpv6PayloadSlice::RouterSolicitation(value) => value.slice(),
            Icmpv6PayloadSlice::RouterAdvertisement(value) => value.slice(),
            Icmpv6PayloadSlice::NeighborSolicitation(value) => value.slice(),
            Icmpv6PayloadSlice::NeighborAdvertisement(value) => value.slice(),
            Icmpv6PayloadSlice::Redirect(value) => value.slice(),
            Icmpv6PayloadSlice::Raw(value) => value,
        }
    }

    /// Convert the borrowed payload to an owned structured payload if supported.
    pub fn to_payload(&self) -> Option<Icmpv6Payload> {
        match self {
            Icmpv6PayloadSlice::RouterSolicitation(value) => {
                Some(Icmpv6Payload::RouterSolicitation(value.to_payload()))
            }
            Icmpv6PayloadSlice::RouterAdvertisement(value) => {
                Some(Icmpv6Payload::RouterAdvertisement(value.to_payload()))
            }
            Icmpv6PayloadSlice::NeighborSolicitation(value) => {
                Some(Icmpv6Payload::NeighborSolicitation(value.to_payload()))
            }
            Icmpv6PayloadSlice::NeighborAdvertisement(value) => {
                Some(Icmpv6Payload::NeighborAdvertisement(value.to_payload()))
            }
            Icmpv6PayloadSlice::Redirect(value) => Some(Icmpv6Payload::Redirect(value.to_payload())),
            Icmpv6PayloadSlice::Raw(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{err, err::Layer, LenSource};
    use crate::icmpv6::{
        NeighborAdvertisementPayload, NeighborSolicitationPayload, RedirectPayload,
        RouterAdvertisementPayload, RouterSolicitationPayload,
    };
    use core::net::Ipv6Addr;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn router_solicitation(slice in proptest::collection::vec(any::<u8>(), 0..64)) {
            let actual = RouterSolicitationPayloadSlice::from_slice(&slice).unwrap();
            assert_eq!(actual.slice(), &slice[..]);
            assert_eq!(actual.options(), &slice[..]);
            assert_eq!(actual.to_payload(), RouterSolicitationPayload);
        }

        #[test]
        fn router_advertisement(
            reachable_time in any::<u32>(),
            retrans_timer in any::<u32>(),
            options in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let mut data = [0u8; 8];
            data[..4].copy_from_slice(&reachable_time.to_be_bytes());
            data[4..].copy_from_slice(&retrans_timer.to_be_bytes());
            let mut payload = alloc::vec::Vec::from(data);
            payload.extend_from_slice(&options);

            let actual = RouterAdvertisementPayloadSlice::from_slice(&payload).unwrap();
            assert_eq!(actual.reachable_time(), reachable_time);
            assert_eq!(actual.retrans_timer(), retrans_timer);
            assert_eq!(actual.options(), &options[..]);
            assert_eq!(
                actual.to_payload(),
                RouterAdvertisementPayload {
                    reachable_time,
                    retrans_timer,
                }
            );
        }

        #[test]
        fn neighbor_solicitation(
            target_address in any::<[u8;16]>(),
            options in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let mut payload = alloc::vec::Vec::from(target_address);
            payload.extend_from_slice(&options);
            let actual = NeighborSolicitationPayloadSlice::from_slice(&payload).unwrap();
            assert_eq!(actual.target_address(), Ipv6Addr::from(target_address));
            assert_eq!(actual.options(), &options[..]);
            assert_eq!(
                actual.to_payload(),
                NeighborSolicitationPayload {
                    target_address: Ipv6Addr::from(target_address)
                }
            );
        }

        #[test]
        fn neighbor_advertisement(
            target_address in any::<[u8;16]>(),
            options in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let mut payload = alloc::vec::Vec::from(target_address);
            payload.extend_from_slice(&options);
            let actual = NeighborAdvertisementPayloadSlice::from_slice(&payload).unwrap();
            assert_eq!(actual.target_address(), Ipv6Addr::from(target_address));
            assert_eq!(actual.options(), &options[..]);
            assert_eq!(
                actual.to_payload(),
                NeighborAdvertisementPayload {
                    target_address: Ipv6Addr::from(target_address),
                }
            );
        }

        #[test]
        fn redirect(
            target_address in any::<[u8;16]>(),
            destination_address in any::<[u8;16]>(),
            options in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let mut payload = alloc::vec::Vec::from(target_address);
            payload.extend_from_slice(&destination_address);
            payload.extend_from_slice(&options);
            let actual = RedirectPayloadSlice::from_slice(&payload).unwrap();
            assert_eq!(actual.target_address(), Ipv6Addr::from(target_address));
            assert_eq!(actual.destination_address(), Ipv6Addr::from(destination_address));
            assert_eq!(actual.options(), &options[..]);
            assert_eq!(
                actual.to_payload(),
                RedirectPayload {
                    target_address: Ipv6Addr::from(target_address),
                    destination_address: Ipv6Addr::from(destination_address),
                }
            );
        }
    }

    #[test]
    fn len_errors() {
        assert_eq!(
            Err(err::LenError {
                required_len: RouterAdvertisementPayloadSlice::FIXED_PART_LEN,
                len: 7,
                len_source: LenSource::Slice,
                layer: Layer::Icmpv6,
                layer_start_offset: 0,
            }),
            RouterAdvertisementPayloadSlice::from_slice(&[0; 7])
        );
        assert_eq!(
            Err(err::LenError {
                required_len: NeighborSolicitationPayloadSlice::FIXED_PART_LEN,
                len: 15,
                len_source: LenSource::Slice,
                layer: Layer::Icmpv6,
                layer_start_offset: 0,
            }),
            NeighborSolicitationPayloadSlice::from_slice(&[0; 15])
        );
        assert_eq!(
            Err(err::LenError {
                required_len: NeighborAdvertisementPayloadSlice::FIXED_PART_LEN,
                len: 15,
                len_source: LenSource::Slice,
                layer: Layer::Icmpv6,
                layer_start_offset: 0,
            }),
            NeighborAdvertisementPayloadSlice::from_slice(&[0; 15])
        );
        assert_eq!(
            Err(err::LenError {
                required_len: RedirectPayloadSlice::FIXED_PART_LEN,
                len: 31,
                len_source: LenSource::Slice,
                layer: Layer::Icmpv6,
                layer_start_offset: 0,
            }),
            RedirectPayloadSlice::from_slice(&[0; 31])
        );
    }
}
