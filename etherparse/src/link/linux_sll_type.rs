use crate::err::{self, ValueTooBigError};

/// Represents the type of direction that the packet contained in the 
/// LINUX_SLL packet
/// 
/// You can convert `u16` in the valid range to an `LinuxSllType` and the 
/// other way around
/// 
/// ```
/// use etherparse::LinuxSllType;
///
/// // Convert to LinuxSllType using the try_from & try_into trait
/// let link_type: LinuxSllType = 1_u16.try_into().unwrap();
/// assert_eq!(LinuxSllType::BroadcastByOther, link_type);
///
/// // convert to u16 using the from & into trait
/// let num: u16 = LinuxSllType::BroadcastByOther.into();
/// assert_eq!(1, num);
/// ```
/// 
#[derive(Clone, Copy, Eq, PartialEq, Default)]
pub enum LinuxSllType {
    /// The packet was specifically sent by other to the one that captured the
    /// packet
    #[default]
    UnicastByOtherToReceiver,
    /// The packet was multicasted by somebody else
    BroadcastByOther,
    /// The packet was broadcasted by somebody else
    MulticastByOther,
    /// The packet was sent by other to another
    UnicastByOtherToOther,
    /// The packet was sent by the one that captured the packet
    SentByUs,
}

impl LinuxSllType {
    /// Asociated u16 value of `LinuxSllType::UnicastByOtherToReceiver`
    pub const UNICAST_BY_OTHER_TO_US: u16 = 0;
    /// Asociated u16 value of `LinuxSllType::BroadcastByOther`
    pub const BROADCAST_BY_OTHER: u16 = 1;
    /// Asociated u16 value of `LinuxSllType::MulticastByOther`
    pub const MULTICAST_BY_OTHER: u16 = 2;
    /// Asociated u16 value of `LinuxSllType::UnicastByOtherToOther`
    pub const UNICAST_BY_OTHER_TO_OTHER: u16 = 3;
    /// Asociated u16 value of `LinuxSllType::UnicastByOtherToOther`
    pub const SENT_BY_US: u16 = 4;
    /// Maximum associated value
    pub const MAX_U16: u16 = 4;
}

impl TryFrom<u16> for LinuxSllType {
    type Error = ValueTooBigError<u16>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            LinuxSllType::UNICAST_BY_OTHER_TO_US => Ok(LinuxSllType::UnicastByOtherToReceiver),
            LinuxSllType::BROADCAST_BY_OTHER => Ok(LinuxSllType::BroadcastByOther),
            LinuxSllType::MULTICAST_BY_OTHER => Ok(LinuxSllType::MulticastByOther),
            LinuxSllType::UNICAST_BY_OTHER_TO_OTHER => Ok(LinuxSllType::UnicastByOtherToOther),
            LinuxSllType::SENT_BY_US => Ok(LinuxSllType::SentByUs),
            LinuxSllType::MAX_U16..=u16::MAX => Err(ValueTooBigError {
                actual: value,
                max_allowed: LinuxSllType::MAX_U16,
                value_type: err::ValueType::LinuxSllType,
            }),
        }
    }
}

impl From<LinuxSllType> for u16 {
    #[inline]
    fn from(value: LinuxSllType) -> Self {
        match value {
            LinuxSllType::UnicastByOtherToReceiver => LinuxSllType::UNICAST_BY_OTHER_TO_US,
            LinuxSllType::BroadcastByOther => LinuxSllType::BROADCAST_BY_OTHER,
            LinuxSllType::MulticastByOther => LinuxSllType::MULTICAST_BY_OTHER,
            LinuxSllType::UnicastByOtherToOther => LinuxSllType::UNICAST_BY_OTHER_TO_OTHER,
            LinuxSllType::SentByUs => LinuxSllType::SENT_BY_US,
        }
    }
}

impl core::fmt::Debug for LinuxSllType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LinuxSllType::UnicastByOtherToReceiver => write!(f, "Unicast by other to receiver ({})", u16::from(*self)),
            LinuxSllType::BroadcastByOther => write!(f, "Broadcast by other ({})", u16::from(*self)),
            LinuxSllType::MulticastByOther => write!(f, "Multicast by other to receiver ({})", u16::from(*self)),
            LinuxSllType::UnicastByOtherToOther => write!(f, "Unicast by other to other ({})", u16::from(*self)),
            LinuxSllType::SentByUs => write!(f, "Sent by us ({})", u16::from(*self)),
        }
    }
}

#[cfg(test)]
mod test {
    use alloc::format;

    use super::*;
    use crate::err::{self, ValueTooBigError};

    #[test]
    fn to_u16() {
        assert_eq!(0, u16::from(LinuxSllType::UnicastByOtherToReceiver));
        assert_eq!(1, u16::from(LinuxSllType::BroadcastByOther));
        assert_eq!(2, u16::from(LinuxSllType::MulticastByOther));
        assert_eq!(3, u16::from(LinuxSllType::UnicastByOtherToOther));
        assert_eq!(4, u16::from(LinuxSllType::SentByUs));
    }

    #[test]
    fn try_from_u16() {
        assert_eq!(LinuxSllType::try_from(0), Ok(LinuxSllType::UnicastByOtherToReceiver));
        assert_eq!(LinuxSllType::try_from(1), Ok(LinuxSllType::BroadcastByOther));
        assert_eq!(LinuxSllType::try_from(2), Ok(LinuxSllType::MulticastByOther));
        assert_eq!(LinuxSllType::try_from(3), Ok(LinuxSllType::UnicastByOtherToOther));
        assert_eq!(LinuxSllType::try_from(4), Ok(LinuxSllType::SentByUs));
        assert_eq!(LinuxSllType::try_from(5), Err(ValueTooBigError {
            actual: 5,
            max_allowed: LinuxSllType::MAX_U16,
            value_type: err::ValueType::LinuxSllType,
        }));
        assert_eq!(LinuxSllType::try_from(123), Err(ValueTooBigError {
            actual: 123,
            max_allowed: LinuxSllType::MAX_U16,
            value_type: err::ValueType::LinuxSllType,
        }));
    }

    #[test]
    fn dbg() {
        let pairs = &[
            (
                LinuxSllType::UnicastByOtherToReceiver,
                "Unicast by other to receiver (0)",
            ),
            (
                LinuxSllType::BroadcastByOther,
                "Broadcast by other (1)",
            ),
            (
                LinuxSllType::MulticastByOther,
                "Multicast by other to receiver (2)"
            ),
            (
                LinuxSllType::UnicastByOtherToOther,
                "Unicast by other to other (3)"
            ),
            (
                LinuxSllType::SentByUs,
                "Sent by us (4)"
            ),
        ];

        for (ether_type, str_value) in pairs {
            assert_eq!(str_value, &format!("{:?}", ether_type));
        }
    }

    #[test]
    fn default() {
        let value: LinuxSllType = Default::default();
        assert_eq!(LinuxSllType::UnicastByOtherToReceiver, value);
    }

    #[test]
    fn clone_eq() {
        let values = &[
            LinuxSllType::UnicastByOtherToReceiver,
            LinuxSllType::BroadcastByOther,
            LinuxSllType::MulticastByOther,
            LinuxSllType::UnicastByOtherToOther,
            LinuxSllType::SentByUs,
        ];

        // clone
        for v in values {
            assert_eq!(v, &v.clone());
        }

        // eq
        for (a_pos, a) in values.iter().enumerate() {
            for (b_pos, b) in values.iter().enumerate() {
                assert_eq!(a_pos == b_pos, a == b);
                assert_eq!(a_pos != b_pos, a != b);
            }
        }
    }
}
