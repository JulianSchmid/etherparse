#[derive(Clone)]
pub struct IpAuthIcv {
    pub(crate) len: u8,
    pub(crate) buf: [u8; 40],
}
