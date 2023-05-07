use crate::err::ValueTooBigError;

/// 2 bit unsigned integer containing the "Explicit Congestion
/// Notification" (present in the [`Ipv4Header`]).
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv4Ecn(u8);

impl Ipv4Ecn {
    /// Ipv4Ecn with value 0.
    pub const ZERO: Ipv4Ecn = Ipv4Ecn(0);

    /// Ipv4Ecn with value 0.
    pub const ONE: Ipv4Ecn = Ipv4Ecn(1);

    /// Ipv4Ecn with value 0.
    pub const TWO: Ipv4Ecn = Ipv4Ecn(2);

    /// Ipv4Ecn with value 0.
    pub const TRHEE: Ipv4Ecn = Ipv4Ecn(3);

    /// Maximum value of an IPv4 header ECN.
    pub const MAX_U8: u8 = 0b0000_0011;

    /// Tries to create an [`Ipv4Ecn`] and checks that the passed value
    /// is smaller or equal than [`Ipv4Ecn::MAX_U8`] (2 bit unsigned integer).
    ///
    /// In case the passed value is bigger then what can be represented in an 2 bit
    /// integer an error is returned. Otherwise an `Ok` containing the [`Ipv4Ecn`].
    ///
    /// ```
    /// use etherparse::Ipv4Ecn;
    ///
    /// let ecn = Ipv4Ecn::try_new(2).unwrap();
    /// assert_eq!(ecn.value(), 2);
    ///
    /// // if a number that can not be represented in an 2 bit integer
    /// // gets passed in an error is returned
    /// use etherparse::err::{ValueTooBigError, ValueType};
    /// assert_eq!(
    ///     Ipv4Ecn::try_new(Ipv4Ecn::MAX_U8 + 1),
    ///     Err(ValueTooBigError{
    ///         actual: Ipv4Ecn::MAX_U8 + 1,
    ///         max_allowed: Ipv4Ecn::MAX_U8,
    ///         value_type: ValueType::Ipv4Ecn,
    ///     })
    /// );
    /// ```
    #[inline]
    pub const fn try_new(value: u8) -> Result<Ipv4Ecn, ValueTooBigError<u8>> {
        use crate::err::ValueType;
        if value <= Ipv4Ecn::MAX_U8 {
            Ok(Ipv4Ecn(value))
        } else {
            Err(ValueTooBigError {
                actual: value,
                max_allowed: Ipv4Ecn::MAX_U8,
                value_type: ValueType::Ipv4Ecn,
            })
        }
    }

    /// Creates an [`Ipv4Ecn`] without checking that the value
    /// is smaller or equal than [`Ipv4Ecn::MAX_U8`] (2 bit unsigned integer).
    /// The caller must gurantee that `value <= Ipv4Ecn::MAX_U8`.
    ///
    /// # Safety
    ///
    /// `value` must be smaller or equal than [`Ipv4Ecn::MAX_U8`]
    /// otherwise the behaviour of functions or datastructures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const unsafe fn new_unchecked(value: u8) -> Ipv4Ecn {
        debug_assert!(value <= Ipv4Ecn::MAX_U8);
        Ipv4Ecn(value)
    }

    /// Returns the underlying unsigned 2 bit value as an `u8` value.
    #[inline]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for Ipv4Ecn {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Ipv4Ecn> for u8 {
    #[inline]
    fn from(value: Ipv4Ecn) -> Self {
        value.0
    }
}

impl TryFrom<u8> for Ipv4Ecn {
    type Error = ValueTooBigError<u8>;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use crate::err::ValueType;
        if value <= Ipv4Ecn::MAX_U8 {
            Ok(Ipv4Ecn(value))
        } else {
            Err(Self::Error {
                actual: value,
                max_allowed: Ipv4Ecn::MAX_U8,
                value_type: ValueType::Ipv4Ecn,
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
            let a = Ipv4Ecn(2);
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // default
        {
            let actual: Ipv4Ecn = Default::default();
            assert_eq!(actual.value(), 0);
        }

        // debug
        {
            let a = Ipv4Ecn(2);
            assert_eq!(format!("{:?}", a), format!("Ipv4Ecn(2)"));
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = Ipv4Ecn(2);
            let b = a;
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                Ipv4Ecn(2).hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                Ipv4Ecn(2).hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }

    proptest! {
        #[test]
        fn try_new(
            valid_value in 0..=0b0000_0011u8,
            invalid_value in 0b0000_0100u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            assert_eq!(
                valid_value,
                Ipv4Ecn::try_new(valid_value).unwrap().value()
            );
            assert_eq!(
                Ipv4Ecn::try_new(invalid_value).unwrap_err(),
                ValueTooBigError{
                    actual: invalid_value,
                    max_allowed: 0b0000_0011,
                    value_type:  ValueType::Ipv4Ecn
                }
            );
        }
    }

    proptest! {
        #[test]
        fn try_from(
            valid_value in 0..=0b0000_0011u8,
            invalid_value in 0b0000_0100u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            // try_into
            {
                let actual: Ipv4Ecn = valid_value.try_into().unwrap();
                assert_eq!(actual.value(), valid_value);

                let err: Result<Ipv4Ecn, ValueTooBigError<u8>> = invalid_value.try_into();
                assert_eq!(
                    err.unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0000_0011,
                        value_type:  ValueType::Ipv4Ecn
                    }
                );
            }
            // try_from
            {
                assert_eq!(
                    Ipv4Ecn::try_from(valid_value).unwrap().value(),
                    valid_value
                );

                assert_eq!(
                    Ipv4Ecn::try_from(invalid_value).unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0000_0011,
                        value_type:  ValueType::Ipv4Ecn
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn new_unchecked(valid_value in 0..=0b0000_0011u8) {
            assert_eq!(
                valid_value,
                unsafe {
                    Ipv4Ecn::new_unchecked(valid_value).value()
                }
            );
        }
    }

    proptest! {
        #[test]
        fn fmt(valid_value in 0..=0b0000_0011u8) {
            assert_eq!(format!("{}", Ipv4Ecn(valid_value)), format!("{}", valid_value));
        }
    }

    proptest! {
        #[test]
        fn from(valid_value in 0..=0b0000_0011u8,) {
            let ecn = Ipv4Ecn::try_new(valid_value).unwrap();
            let actual: u8 = ecn.into();
            assert_eq!(actual, valid_value);
        }
    }
}
