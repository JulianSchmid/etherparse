
/// A ICMPv4 timestamp or timestamp response message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimestampMessage {
    pub id: u16,
    pub seq: u16,
    pub originate_timestamp: u32,
    pub receive_timestamp: u32,
    pub transmit_timestamp: u32,
}

impl TimestampMessage {
    /// Deprecated use [`TimestampMessage::LEN`] instead.
    #[deprecated(since = "0.14.0", note = "Use `TimestampMessage::LEN` instead")]
    pub const SERIALIZED_SIZE: usize = 20;

    /// The size in bytes/octets of a timestamp request or timestamp response message.
    pub const LEN: usize = 20;

    /// Decodes the timestamp message part of an ICMPv4 message.
    pub fn from_bytes(bytes: [u8; 16]) -> TimestampMessage {
        TimestampMessage {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            seq: u16::from_be_bytes([bytes[2], bytes[3]]),
            originate_timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            receive_timestamp: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            transmit_timestamp: u32::from_be_bytes([
                bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
        }
    }
}