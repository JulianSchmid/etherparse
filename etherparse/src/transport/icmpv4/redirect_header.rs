use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectHeader {
    pub code: RedirectCode,
    pub gateway_internet_address: [u8; 4],
}
