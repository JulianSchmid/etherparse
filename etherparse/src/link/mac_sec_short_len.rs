use crate::err::ValueTooBigError;

/// 6 bit unsigned integer containing the "MACsec short length".
/// (present in the [`crate::MacSecHeader`]).
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MacSecShortLen(u8);

impl MacSecShortLen {
    /// MacSecSl with value 0.
    pub const ZERO: MacSecShortLen = MacSecShortLen(0);

    /// Maximum value of a "MACsec short length".
    pub const MAX_U8: u8 = 0b0011_1111;

    /// Tries to create an [`MacSecSl`] and checks that the passed value
    /// is smaller or equal than [`MacSecSl::MAX_U8`] (6 bit unsigned integer).
    ///
    /// In case the passed value is bigger then what can be represented in an 6 bit
    /// integer an error is returned. Otherwise an `Ok` containing the [`MacSecSl`].
    ///
    /// ```
    /// use etherparse::MacSecSl;
    ///
    /// let an = MacSecSl::try_new(2).unwrap();
    /// assert_eq!(an.value(), 2);
    ///
    /// // if a number that can not be represented in an 2 bit integer
    /// // gets passed in an error is returned
    /// use etherparse::err::{ValueTooBigError, ValueType};
    /// assert_eq!(
    ///     MacSecSl::try_new(MacSecSl::MAX_U8 + 1),
    ///     Err(ValueTooBigError{
    ///         actual: MacSecSl::MAX_U8 + 1,
    ///         max_allowed: MacSecSl::MAX_U8,
    ///         value_type: ValueType::MacSecSl,
    ///     })
    /// );
    /// ```
    #[inline]
    pub const fn try_new(value: u8) -> Result<MacSecShortLen, ValueTooBigError<u8>> {
        use crate::err::ValueType;
        if value <= MacSecShortLen::MAX_U8 {
            Ok(MacSecShortLen(value))
        } else {
            Err(ValueTooBigError {
                actual: value,
                max_allowed: MacSecShortLen::MAX_U8,
                value_type: ValueType::MacSecSl,
            })
        }
    }

    /// Creates an [`MacSecSl`] without checking that the value
    /// is smaller or equal than [`MacSecSl::MAX_U8`] (6 bit unsigned integer).
    /// The caller must guarantee that `value <= MacSecSl::MAX_U8`.
    ///
    /// # Safety
    ///
    /// `value` must be smaller or equal than [`MacSecSl::MAX_U8`]
    /// otherwise the behavior of functions or data structures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const unsafe fn new_unchecked(value: u8) -> MacSecShortLen {
        debug_assert!(value <= MacSecShortLen::MAX_U8);
        MacSecShortLen(value)
    }

    /// Returns the underlying unsigned 6 bit value as an `u8` value.
    #[inline]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for MacSecShortLen {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<MacSecShortLen> for u8 {
    #[inline]
    fn from(value: MacSecShortLen) -> Self {
        value.0
    }
}

impl TryFrom<u8> for MacSecShortLen {
    type Error = ValueTooBigError<u8>;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use crate::err::ValueType;
        if value <= MacSecShortLen::MAX_U8 {
            Ok(MacSecShortLen(value))
        } else {
            Err(Self::Error {
                actual: value,
                max_allowed: MacSecShortLen::MAX_U8,
                value_type: ValueType::MacSecSl,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::format;

    #[test]
    fn derived_traits() {
        // copy & clone
        {
            let a = MacSecShortLen(2);
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // default
        {
            let actual: MacSecShortLen = Default::default();
            assert_eq!(actual.value(), 0);
        }

        // debug
        {
            let a = MacSecShortLen(2);
            assert_eq!(format!("{:?}", a), format!("MacSecSl(2)"));
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = MacSecShortLen(2);
            let b = a;
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                MacSecShortLen(2).hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                MacSecShortLen(2).hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }

    proptest! {
        #[test]
        fn try_new(
            valid_value in 0..=0b0011_1111u8,
            invalid_value in 0b0100_0000u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            assert_eq!(
                valid_value,
                MacSecShortLen::try_new(valid_value).unwrap().value()
            );
            assert_eq!(
                MacSecShortLen::try_new(invalid_value).unwrap_err(),
                ValueTooBigError{
                    actual: invalid_value,
                    max_allowed: 0b0011_1111,
                    value_type:  ValueType::MacSecSl
                }
            );
        }
    }

    proptest! {
        #[test]
        fn try_from(
            valid_value in 0..=0b0011_1111u8,
            invalid_value in 0b0100_0000u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            // try_into
            {
                let actual: MacSecShortLen = valid_value.try_into().unwrap();
                assert_eq!(actual.value(), valid_value);

                let err: Result<MacSecShortLen, ValueTooBigError<u8>> = invalid_value.try_into();
                assert_eq!(
                    err.unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0011_1111,
                        value_type:  ValueType::MacSecSl
                    }
                );
            }
            // try_from
            {
                assert_eq!(
                    MacSecShortLen::try_from(valid_value).unwrap().value(),
                    valid_value
                );

                assert_eq!(
                    MacSecShortLen::try_from(invalid_value).unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0011_1111,
                        value_type:  ValueType::MacSecSl
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn new_unchecked(valid_value in 0..=0b0011_1111u8) {
            assert_eq!(
                valid_value,
                unsafe {
                    MacSecShortLen::new_unchecked(valid_value).value()
                }
            );
        }
    }

    proptest! {
        #[test]
        fn fmt(valid_value in 0..=0b0011_1111u8) {
            assert_eq!(format!("{}", MacSecShortLen(valid_value)), format!("{}", valid_value));
        }
    }

    proptest! {
        #[test]
        fn from(valid_value in 0..=0b0011_1111u8,) {
            let pcp = MacSecShortLen::try_new(valid_value).unwrap();
            let actual: u8 = pcp.into();
            assert_eq!(actual, valid_value);
        }
    }
}
