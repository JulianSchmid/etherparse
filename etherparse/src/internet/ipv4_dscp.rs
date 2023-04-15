use crate::err::ValueTooBigError;

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv4Dscp(u8);

impl Ipv4Dscp {
    /// Ipv4Dscp with value 0.
    pub const ZERO: Ipv4Dscp = Ipv4Dscp(0);

    /// Maximum value of an IPv4 header DSCP.
    pub const MAX_U8: u8 = 0b0011_1111;

    /// Tries to create an [`Ipv4Dscp`] and checks that the passed value
    /// is smaller or equal than [`Ipv4Dscp::MAX_U8`] (6 bit unsigned integer).
    ///
    /// In case the passed value is bigger then what can be represented in an 6 bit
    /// integer an error is returned. Otherwise an `Ok` containing the [`Ipv4Dscp`].
    ///
    /// ```
    /// use etherparse::Ipv4Dscp;
    ///
    /// let dscp = Ipv4Dscp::try_new(32).unwrap();
    /// assert_eq!(dscp.value(), 32);
    ///
    /// // if a number that can not be represented in an 6 bit integer
    /// // gets passed in an error is returned
    /// use etherparse::err::{ValueTooBigError, ValueType};
    /// assert_eq!(
    ///     Ipv4Dscp::try_new(Ipv4Dscp::MAX_U8 + 1),
    ///     Err(ValueTooBigError{
    ///         actual: Ipv4Dscp::MAX_U8 + 1,
    ///         max_allowed: Ipv4Dscp::MAX_U8,
    ///         value_type: ValueType::Ipv4Dscp,
    ///     })
    /// );
    /// ```
    ///
    /// # Safety
    ///
    /// `value` must be smaller or equal than [`Ipv4Dscp::MAX_U16`]
    /// otherwise the behaviour of functions or datastructures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const fn try_new(value: u8) -> Result<Ipv4Dscp, ValueTooBigError<u8>> {
        use crate::err::ValueType;
        if value <= Ipv4Dscp::MAX_U8 {
            Ok(Ipv4Dscp(value))
        } else {
            Err(ValueTooBigError {
                actual: value,
                max_allowed: Ipv4Dscp::MAX_U8,
                value_type: ValueType::Ipv4Dscp,
            })
        }
    }

    /// Creates an [`Ipv4Dscp`] without checking that the value
    /// is smaller or equal than [`Ipv4Dscp::MAX_U8`] (6 bit unsigned integer).
    /// The caller must gurantee that `value <= Ipv4Dscp::MAX_U8`.
    ///
    /// # Safety
    ///
    /// `value` must be smaller or equal than [`Ipv4Dscp::MAX_U8`]
    /// otherwise the behaviour of functions or datastructures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const unsafe fn new_unchecked(value: u8) -> Ipv4Dscp {
        debug_assert!(value <= Ipv4Dscp::MAX_U8);
        Ipv4Dscp(value)
    }

    /// Returns the underlying unsigned 6 bit value as an `u8` value.
    #[inline]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for Ipv4Dscp {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Ipv4Dscp> for u8 {
    #[inline]
    fn from(value: Ipv4Dscp) -> Self {
        value.0
    }
}

impl TryFrom<u8> for Ipv4Dscp {
    type Error = ValueTooBigError<u8>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use crate::err::ValueType;
        if value <= Ipv4Dscp::MAX_U8 {
            Ok(Ipv4Dscp(value))
        } else {
            Err(Self::Error {
                actual: value,
                max_allowed: Ipv4Dscp::MAX_U8,
                value_type: ValueType::Ipv4Dscp,
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
            let a = Ipv4Dscp(64);
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // default
        {
            let actual: Ipv4Dscp = Default::default();
            assert_eq!(actual.value(), 0);
        }

        // debug
        {
            let a = Ipv4Dscp(64);
            assert_eq!(format!("{:?}", a), format!("Ipv4Dscp(64)"));
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = Ipv4Dscp(64);
            let b = a;
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                Ipv4Dscp(64).hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                Ipv4Dscp(64).hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }

    proptest! {
        #[test]
        fn try_new(
            valid_value in 0..0b0011_1111u8,
            invalid_value in 0b0100_0000u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            assert_eq!(
                valid_value,
                Ipv4Dscp::try_new(valid_value).unwrap().value()
            );
            assert_eq!(
                Ipv4Dscp::try_new(invalid_value).unwrap_err(),
                ValueTooBigError{
                    actual: invalid_value,
                    max_allowed: 0b0011_1111,
                    value_type:  ValueType::Ipv4Dscp
                }
            );
        }
    }

    proptest! {
        #[test]
        fn try_from(
            valid_value in 0..0b0011_1111u8,
            invalid_value in 0b0100_0000u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            // try_into
            {
                let actual: Ipv4Dscp = valid_value.try_into().unwrap();
                assert_eq!(actual.value(), valid_value);

                let err: Result<Ipv4Dscp, ValueTooBigError<u8>> = invalid_value.try_into();
                assert_eq!(
                    err.unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0011_1111,
                        value_type:  ValueType::Ipv4Dscp
                    }
                );
            }
            // try_from
            {
                assert_eq!(
                    Ipv4Dscp::try_from(valid_value).unwrap().value(),
                    valid_value
                );

                assert_eq!(
                    Ipv4Dscp::try_from(invalid_value).unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0011_1111,
                        value_type:  ValueType::Ipv4Dscp
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn new_unchecked(valid_value in 0..0b0011_1111u8) {
            assert_eq!(
                valid_value,
                unsafe {
                    Ipv4Dscp::new_unchecked(valid_value).value()
                }
            );
        }
    }

    proptest! {
        #[test]
        fn fmt(valid_value in 0..0b0011_1111u8) {
            assert_eq!(format!("{}", Ipv4Dscp(valid_value)), format!("{}", valid_value));
        }
    }

    proptest! {
        #[test]
        fn from(valid_value in 0..0b0011_1111u8,) {
            let frag_offset = Ipv4Dscp::try_new(valid_value).unwrap();
            let actual: u8 = frag_offset.into();
            assert_eq!(actual, valid_value);
        }
    }
}
