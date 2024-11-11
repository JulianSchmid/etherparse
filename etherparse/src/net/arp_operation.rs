#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpOperation(pub u16);

impl ArpOperation {
    pub const REQUEST: ArpOperation = ArpOperation(1);
    pub const REPLY: ArpOperation = ArpOperation(2);
}

impl From<u16> for ArpOperation {
    fn from(raw: u16) -> Self {
        ArpOperation(raw)
    }
}
