#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighbourAdverisementHeader {
    pub router: bool,
    pub solicited: bool,
    pub r#override: bool,
}

const ROUTER_MASK: u8 = 0b10000000;
const SOLICITED_MASK: u8 = 0b01000000;
const OVERRIDE_MASK: u8 = 0b00100000;

impl NeighbourAdverisementHeader {
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        let first_byte = bytes[0];

        Self {
            router: (first_byte & ROUTER_MASK) == ROUTER_MASK,
            solicited: (first_byte & SOLICITED_MASK) == SOLICITED_MASK,
            r#override: (first_byte & OVERRIDE_MASK) == OVERRIDE_MASK,
        }
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let mut first_byte = 0u8;

        if self.router {
            first_byte |= ROUTER_MASK;
        }
        if self.solicited {
            first_byte |= SOLICITED_MASK;
        }
        if self.r#override {
            first_byte |= OVERRIDE_MASK;
        }

        [first_byte, 0, 0, 0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_router_bit_correctly() {
        assert!(NeighbourAdverisementHeader::from_bytes([0b10000000, 0, 0, 0]).router);
        assert!(!NeighbourAdverisementHeader::from_bytes([0, 0, 0, 0]).router);
    }

    #[test]
    fn reads_solicited_bit_correctly() {
        assert!(NeighbourAdverisementHeader::from_bytes([0b01000000, 0, 0, 0]).solicited);
        assert!(!NeighbourAdverisementHeader::from_bytes([0, 0, 0, 0]).solicited);
    }

    #[test]
    fn reads_override_bit_correctly() {
        assert!(NeighbourAdverisementHeader::from_bytes([0b00100000, 0, 0, 0]).r#override);
        assert!(!NeighbourAdverisementHeader::from_bytes([0, 0, 0, 0]).r#override);
    }

    #[test]
    fn reads_combined_bit_correctly() {
        let header = NeighbourAdverisementHeader::from_bytes([0b11100000, 0, 0, 0]);

        assert!(header.router);
        assert!(header.solicited);
        assert!(header.r#override);
    }
}
