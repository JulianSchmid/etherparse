/// Max response code (specifies the maximum time allowed before
/// sending a responding report in IGMPv3).
///
/// The actual time allowed, called the Max
/// Resp Time, is represented in units of 1/10 second and is derived from
/// the Max Resp Code as follows:
///
/// If Max Resp Code < 128, Max Resp Time = Max Resp Code
///
/// If Max Resp Code >= 128, Max Resp Code represents a floating-point
/// value as follows:
///
/// ```text
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |1| exp | mant  |
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// Max Resp Time = (mant | 0x10) << (exp + 3)
///
/// Small values of Max Resp Time allow IGMPv3 routers to tune the "leave
/// latency" (the time between the moment the last host leaves a group
/// and the moment the routing protocol is notified that there are no
/// more members).  Larger values, especially in the exponential range,
/// allow tuning of the burstiness of IGMP traffic on a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaxResponseCode(pub u8);

impl MaxResponseCode {
    /// Returns the max response time in 10th seconds (converts raw value).
    pub fn as_10th_secs(&self) -> u16 {
        if 0 != self.0 & 0b1000_0000 {
            u16::from((self.0 & 0b0000_1111) | 0x10) << u16::from(((self.0 & 0b0111_0000) >> 4) + 3)
        } else {
            u16::from(self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::format;

    proptest! {
        #[test]
        fn as_10th_secs_linear_range(raw in 0u8..=0b0111_1111u8) {
            prop_assert_eq!(MaxResponseCode(raw).as_10th_secs(), u16::from(raw));
        }

        #[test]
        fn as_10th_secs_exponential_range(mant in 0u8..=0b1111, exp in 0u8..=0b111u8) {
            let raw = 0b1000_0000 | (exp << 4) | mant;
            let expected = u16::from(mant | 0x10) << u16::from(exp + 3);
            prop_assert_eq!(MaxResponseCode(raw).as_10th_secs(), expected);
        }
    }
}
