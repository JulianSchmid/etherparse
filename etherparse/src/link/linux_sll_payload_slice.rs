use crate::LinuxSllProtocolType;


/// Payload of Linux Cooked Capture v1 (SLL) packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSllPayloadSlice<'a> {
    /// Identifying content of the payload.
    pub protocol_type: LinuxSllProtocolType,

    /// Payload
    pub payload: &'a [u8],
}


#[cfg(test)]
mod test {
    use crate::EtherType;

    use super::*;
    use alloc::format;

    #[test]
    fn debug() {
        let s = LinuxSllPayloadSlice {
            protocol_type: LinuxSllProtocolType::EtherType(EtherType::IPV4),
            payload: &[],
        };
        assert_eq!(
            format!(
                "LinuxSllPayloadSlice {{ protocol_type: {:?}, payload: {:?} }}",
                s.protocol_type, s.payload
            ),
            format!("{:?}", s)
        );
    }

    #[test]
    fn clone_eq() {
        let s = LinuxSllPayloadSlice {
            protocol_type: LinuxSllProtocolType::EtherType(EtherType::IPV4),
            payload: &[],
        };
        assert_eq!(s.clone(), s);
    }
}
