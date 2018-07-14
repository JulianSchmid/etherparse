pub mod udp;
pub mod tcp;

use super::*;

///The possible headers on the transport layer
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportHeader {
    Udp(UdpHeader)
}