/// Echo Request & Response common parts between ICMPv4 and ICMPv6.
///
/// # Description from RFC 4443:
///
/// Every node MUST implement an ICMPv6 Echo responder function that
/// receives Echo Requests and originates corresponding Echo Replies.  A
/// node SHOULD also implement an application-layer interface for
/// originating Echo Requests and receiving Echo Replies, for diagnostic
/// purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpEchoHeader {
    /// An identifier to aid in matching Echo Replies to Echo Requests. May be zero.
    pub id: u16,
    /// A sequence number to aid in matching Echo Replies to Echo Requests. May be zero.
    pub seq: u16,
}

impl IcmpEchoHeader {
    /// Return the seq + id encoded to the on the wire format.
    #[inline]
    pub fn to_bytes(&self) -> [u8;4] {
        let id_be = self.id.to_be_bytes();
        let seq_be = self.seq.to_be_bytes();
        [id_be[0], id_be[1], seq_be[0], seq_be[1]]
    }

    /// Decodes the seq + id from the on the wire format.
    #[inline]
    pub fn from_bytes(four_bytes: [u8;4]) -> IcmpEchoHeader {
        IcmpEchoHeader{
            id: u16::from_be_bytes([four_bytes[0], four_bytes[1]]),
            seq: u16::from_be_bytes([four_bytes[2], four_bytes[3]]),
        }
    }
}
