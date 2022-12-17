use super::*;

/// "Destination Unreachable" ICMPv6 code containing a reason why a
/// destination could not be reached.
///
/// # RFC 4443 Description:
///
/// A Destination Unreachable message SHOULD be generated by a router, or
/// by the IPv6 layer in the originating node, in response to a packet
/// that cannot be delivered to its destination address for reasons other
/// than congestion.  (An ICMPv6 message MUST NOT be generated if a
/// packet is dropped due to congestion.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DestUnreachableCode {
    /// No route to destination
    NoRoute = 0,
    /// Communication with destination administratively prohibited
    Prohibited = 1,
    /// Beyond scope of source address
    BeyondScope = 2,
    /// Address unreachable
    Address = 3,
    /// Port unreachable
    Port = 4,
    /// Source address failed ingress/egress policy
    SourceAddressFailedPolicy = 5,
    /// Reject route to destination
    RejectRoute = 6,
}

impl DestUnreachableCode {
    /// Converts the u8 code value from an ICMPv6 "destination unreachable"
    /// packet to an `icmpv6::DestUnreachableCode` enum.
    ///
    /// # Example Usage:
    ///
    /// ```
    /// use etherparse::{icmpv6, icmpv6::DestUnreachableCode};
    /// let icmp_packet: [u8;8] = [
    ///     icmpv6::TYPE_DST_UNREACH, icmpv6::CODE_DST_UNREACH_PORT, 0, 0,
    ///     0, 0, 0, 0,
    /// ];
    ///
    /// if icmpv6::TYPE_DST_UNREACH == icmp_packet[0] {
    ///     let dst = icmpv6::DestUnreachableCode::from_u8(
    ///         icmp_packet[1]
    ///     );
    ///     assert_eq!(dst, Some(icmpv6::DestUnreachableCode::Port));
    /// }
    /// ```
    pub fn from_u8(code_u8: u8) -> Option<DestUnreachableCode> {
        use DestUnreachableCode::*;
        match code_u8 {
            CODE_DST_UNREACH_NO_ROUTE => Some(NoRoute),
            CODE_DST_UNREACH_PROHIBITED => Some(Prohibited),
            CODE_DST_UNREACH_BEYOND_SCOPE => Some(BeyondScope),
            CODE_DST_UNREACH_ADDR => Some(Address),
            CODE_DST_UNREACH_PORT => Some(Port),
            CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY => Some(SourceAddressFailedPolicy),
            CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST => Some(RejectRoute),
            _ => None,
        }
    }

    /// Returns the code value of the destination unreachable packet.
    ///
    /// This is the second byte of an ICMPv6 packet.
    #[inline]
    pub fn code_u8(&self) -> u8 {
        *self as u8
    }
}

#[cfg(test)]
pub(crate) mod dest_unreachable_code_test_consts {
    use super::{DestUnreachableCode::*, *};

    pub const VALID_VALUES: [(DestUnreachableCode, u8); 7] = [
        (NoRoute, CODE_DST_UNREACH_NO_ROUTE),
        (Prohibited, CODE_DST_UNREACH_PROHIBITED),
        (BeyondScope, CODE_DST_UNREACH_BEYOND_SCOPE),
        (Address, CODE_DST_UNREACH_ADDR),
        (Port, CODE_DST_UNREACH_PORT),
        (
            SourceAddressFailedPolicy,
            CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY,
        ),
        (RejectRoute, CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST),
    ];
}

#[cfg(test)]
mod test {
    use super::{dest_unreachable_code_test_consts::*, DestUnreachableCode::*, *};
    use alloc::format;

    #[test]
    fn from_u8() {
        for (code, code_u8) in VALID_VALUES {
            assert_eq!(code, DestUnreachableCode::from_u8(code_u8).unwrap());
        }
        for code_u8 in 7u8..=0xff {
            assert!(DestUnreachableCode::from_u8(code_u8).is_none());
        }
    }

    #[test]
    fn code_u8() {
        for (code, code_u8) in VALID_VALUES {
            assert_eq!(code.code_u8(), code_u8);
        }
    }

    #[test]
    fn clone_eq() {
        for (code, _) in VALID_VALUES {
            assert_eq!(code.clone(), code);
        }
    }

    #[test]
    fn debug() {
        let tests = [
            (NoRoute, "NoRoute"),
            (Prohibited, "Prohibited"),
            (BeyondScope, "BeyondScope"),
            (Address, "Address"),
            (Port, "Port"),
            (SourceAddressFailedPolicy, "SourceAddressFailedPolicy"),
            (RejectRoute, "RejectRoute"),
        ];
        for test in tests {
            assert_eq!(format!("{:?}", test.0), test.1);
        }
    }
}
