/// ICMPv6 neigh
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborAdvertisementHeader {
    pub router: bool,
    pub solicited: bool,
    pub r#override: bool,
}

impl NeighborAdvertisementHeader {
    /// Mask to read out the "router" flag out of the 5th byte of the ICMPv6 header.
    pub const ROUTER_MASK: u8 = 0b10000000;

    /// Mask to read out the "solicited" flag out of the 5th byte of the ICMPv6 header.
    pub const SOLICITED_MASK: u8 = 0b01000000;

    /// Mask to read out the "override" flag out of the 5th byte of the ICMPv6 header.
    pub const OVERRIDE_MASK: u8 = 0b00100000;

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        let first_byte = bytes[0];

        Self {
            router: (first_byte & Self::ROUTER_MASK) == Self::ROUTER_MASK,
            solicited: (first_byte & Self::SOLICITED_MASK) == Self::SOLICITED_MASK,
            r#override: (first_byte & Self::OVERRIDE_MASK) == Self::OVERRIDE_MASK,
        }
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let mut first_byte = 0u8;

        if self.router {
            first_byte |= Self::ROUTER_MASK;
        }
        if self.solicited {
            first_byte |= Self::SOLICITED_MASK;
        }
        if self.r#override {
            first_byte |= Self::OVERRIDE_MASK;
        }

        [first_byte, 0, 0, 0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn to_and_from_bytes(
            router in any::<bool>(),
            solicited in any::<bool>(),
            r#override in any::<bool>()
        ) {
            let bytes = NeighborAdvertisementHeader{
                router,
                solicited,
                r#override
            }.to_bytes();
            assert_eq!(
                NeighborAdvertisementHeader::from_bytes(bytes),
                NeighborAdvertisementHeader {
                    router,
                    solicited,
                    r#override,
                }
            );
        }
    }

    #[test]
    fn reads_router_bit_correctly() {
        assert!(NeighborAdvertisementHeader::from_bytes([0b10000000, 0, 0, 0]).router);
        assert!(!NeighborAdvertisementHeader::from_bytes([0, 0, 0, 0]).router);
    }

    #[test]
    fn reads_solicited_bit_correctly() {
        assert!(NeighborAdvertisementHeader::from_bytes([0b01000000, 0, 0, 0]).solicited);
        assert!(!NeighborAdvertisementHeader::from_bytes([0, 0, 0, 0]).solicited);
    }

    #[test]
    fn reads_override_bit_correctly() {
        assert!(NeighborAdvertisementHeader::from_bytes([0b00100000, 0, 0, 0]).r#override);
        assert!(!NeighborAdvertisementHeader::from_bytes([0, 0, 0, 0]).r#override);
    }

    #[test]
    fn reads_combined_bit_correctly() {
        let header = NeighborAdvertisementHeader::from_bytes([0b11100000, 0, 0, 0]);

        assert!(header.router);
        assert!(header.solicited);
        assert!(header.r#override);
    }
}
