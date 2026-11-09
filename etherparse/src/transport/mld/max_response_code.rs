/// Maximum response code (specifies the maximum time allowed before
/// sending a responding report in MLDv2).
///
/// The actual time allowed, called the "Maximum Response Delay", is
/// represented in units of milliseconds and is derived from the Maximum
/// Response Code as follows:
///
/// If Maximum Response Code < 32768, Maximum Response Delay = Maximum
/// Response Code
///
/// If Maximum Response Code >= 32768, Maximum Response Code represents a
/// floating-point value as follows:
///
/// ```text
///  0 1 2 3 4 5 6 7 8 9 A B C D E F
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |1| exp |          mant         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Maximum Response Delay = (mant | 0x1000) << (exp + 3)
///
/// Small values of Maximum Response Delay allow MLDv2 routers to tune the
/// leave latency (the time between the moment the last node on a link
/// ceases to listen to a specific multicast address and the moment the
/// routing protocol is notified that there are no more listeners for that
/// address). Larger values, especially in the exponential range, allow the
/// tuning of the burstiness of MLD traffic on a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaxResponseCode(pub u16);

impl MaxResponseCode {
    /// Returns the maximum response delay in milliseconds (converts the raw value).
    pub fn as_millis(&self) -> u32 {
        if 0 != self.0 & 0b1000_0000_0000_0000 {
            u32::from((self.0 & 0b0000_1111_1111_1111) | 0x1000)
                << u32::from(((self.0 & 0b0111_0000_0000_0000) >> 12) + 3)
        } else {
            u32::from(self.0)
        }
    }
}

#[cfg(test)]
// the `clone_eq_hash_debug` test deliberately exercises `Clone` even
// though the type is `Copy`.
#[allow(clippy::clone_on_copy)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::format;

    proptest! {
        /// Codes below 32768 are taken as-is, so the delay must equal the
        /// raw value over the whole linear range.
        #[test]
        fn as_millis_linear_range(raw in 0u16..=0b0111_1111_1111_1111u16) {
            prop_assert_eq!(MaxResponseCode(raw).as_millis(), u32::from(raw));
        }

        /// Codes with the top bit set encode a float, so the delay must be
        /// `(mant | 0x1000) << (exp + 3)` for every mantissa & exponent.
        #[test]
        fn as_millis_exponential_range(
            mant in 0u16..=0b1111_1111_1111u16,
            exp in 0u16..=0b111u16,
        ) {
            let raw = 0b1000_0000_0000_0000 | (exp << 12) | mant;
            let expected = u32::from(mant | 0x1000) << u32::from(exp + 3);
            prop_assert_eq!(MaxResponseCode(raw).as_millis(), expected);
        }
    }

    /// Checks the values at the edges of the linear & exponential ranges,
    /// where an off-by-one in the top bit check would show up.
    #[test]
    fn as_millis_boundaries() {
        // last linear value
        assert_eq!(MaxResponseCode(32767).as_millis(), 32767);
        // first exponential value (exp = 0, mant = 0)
        assert_eq!(MaxResponseCode(0x8000).as_millis(), 0x1000 << 3);
        // maximum exponential value (exp = 7, mant = 0xFFF)
        assert_eq!(MaxResponseCode(0xFFFF).as_millis(), 0x1FFF << 10);
    }

    proptest! {
        /// `Clone`, `PartialEq`, `Hash` & `Debug` must be derived and hold
        /// for any raw code.
        #[test]
        fn clone_eq_hash_debug(raw in any::<u16>()) {
            use core::hash::{Hash, Hasher};
            use std::collections::hash_map::DefaultHasher;

            let value = MaxResponseCode(raw);
            prop_assert_eq!(value, value.clone());

            let hash_a = {
                let mut hasher = DefaultHasher::new();
                value.hash(&mut hasher);
                hasher.finish()
            };
            let hash_b = {
                let mut hasher = DefaultHasher::new();
                value.clone().hash(&mut hasher);
                hasher.finish()
            };
            prop_assert_eq!(hash_a, hash_b);

            prop_assert_eq!(format!("{:?}", value), format!("MaxResponseCode({})", raw));
        }
    }
}
