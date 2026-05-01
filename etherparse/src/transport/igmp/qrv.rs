use crate::err::ValueTooBigError;

/// 3 bit unsigned integer containing the "Querier's Robustness Variable"
/// (present in the [`crate::igmp::MembershipQueryWithSourcesHeader`].
///
/// Established in
/// [RFC-3376](https://datatracker.ietf.org/doc/html/rfc3376).
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Qrv(u8);

impl Qrv {
    /// QRV with value 0.
    pub const ZERO: Qrv = Qrv(0);

    /// Maximum value of the IGMPv3 Membership Query QRV.
    pub const MAX_U8: u8 = 0b0000_0111;

    /// Maximum value of the IGMPv3 Membership Query QRV.
    pub const MAX: Qrv = Qrv(Self::MAX_U8);

    /// Static array with all possible values.
    pub const VALUES: [Qrv; 8] = [
        Qrv(0b000),
        Qrv(0b001),
        Qrv(0b010),
        Qrv(0b011),
        Qrv(0b100),
        Qrv(0b101),
        Qrv(0b110),
        Qrv(0b111),
    ];

    /// Tries to create an [`Qrv`] and checks that the passed value
    /// is smaller or equal than [`Qrv::MAX_U8`] (3 bit unsigned integer).
    ///
    /// In case the passed value is bigger then what can be represented in an 3 bit
    /// integer an error is returned. Otherwise an `Ok` containing the [`Qrv`].
    ///
    /// ```
    /// use etherparse::igmp::Qrv;
    ///
    /// let dscp = Qrv::try_new(3).unwrap();
    /// assert_eq!(dscp.value(), 3);
    ///
    /// // if a number that can not be represented in an 3 bit integer
    /// // gets passed in an error is returned
    /// use etherparse::err::{ValueTooBigError, ValueType};
    /// assert_eq!(
    ///     Qrv::try_new(Qrv::MAX_U8 + 1),
    ///     Err(ValueTooBigError{
    ///         actual: Qrv::MAX_U8 + 1,
    ///         max_allowed: Qrv::MAX_U8,
    ///         value_type: ValueType::IgmpQrv,
    ///     })
    /// );
    /// ```
    #[inline]
    pub const fn try_new(value: u8) -> Result<Qrv, ValueTooBigError<u8>> {
        use crate::err::ValueType;
        if value <= Self::MAX_U8 {
            Ok(Qrv(value))
        } else {
            Err(ValueTooBigError {
                actual: value,
                max_allowed: Qrv::MAX_U8,
                value_type: ValueType::IgmpQrv,
            })
        }
    }

    /// Creates an [`Qrv`] without checking that the value
    /// is smaller or equal than [`Qrv::MAX_U8`] (3 bit unsigned integer).
    /// The caller must guarantee that `value <= Qrv::MAX_U8`.
    ///
    /// # Safety
    ///
    /// `value` must be smaller or equal than [`Qrv::MAX_U8`]
    /// otherwise the behavior of functions or data structures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const unsafe fn new_unchecked(value: u8) -> Qrv {
        debug_assert!(value <= Qrv::MAX_U8);
        Qrv(value)
    }

    /// Returns the underlying unsigned 3 bit value as an `u8` value.
    #[inline]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for Qrv {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Qrv> for u8 {
    #[inline]
    fn from(value: Qrv) -> Self {
        value.0
    }
}

impl TryFrom<u8> for Qrv {
    type Error = ValueTooBigError<u8>;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use crate::err::ValueType;
        if value <= Qrv::MAX_U8 {
            Ok(Qrv(value))
        } else {
            Err(Self::Error {
                actual: value,
                max_allowed: Qrv::MAX_U8,
                value_type: ValueType::IgmpQrv,
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
            let a = Qrv(32);
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // default
        {
            let actual: Qrv = Default::default();
            assert_eq!(actual.value(), 0);
        }

        // debug
        {
            let a = Qrv(32);
            assert_eq!(format!("{:?}", a), format!("Qrv(32)"));
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            let a = Qrv(32);
            let b = a;
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let a = {
                let mut hasher = DefaultHasher::new();
                Qrv(64).hash(&mut hasher);
                hasher.finish()
            };
            let b = {
                let mut hasher = DefaultHasher::new();
                Qrv(64).hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(a, b);
        }
    }

    proptest! {
        #[test]
        fn try_new(
            valid_value in 0..=0b0000_0111u8,
            invalid_value in 0b0000_1000u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            assert_eq!(
                valid_value,
                Qrv::try_new(valid_value).unwrap().value()
            );
            assert_eq!(
                Qrv::try_new(invalid_value).unwrap_err(),
                ValueTooBigError{
                    actual: invalid_value,
                    max_allowed: 0b0000_0111,
                    value_type:  ValueType::IgmpQrv
                }
            );
        }
    }

    proptest! {
        #[test]
        fn try_from(
            valid_value in 0..=0b0000_0111u8,
            invalid_value in 0b0000_1000u8..=u8::MAX
        ) {
            use crate::err::{ValueType, ValueTooBigError};
            // try_into
            {
                let actual: Qrv = valid_value.try_into().unwrap();
                assert_eq!(actual.value(), valid_value);

                let err: Result<Qrv, ValueTooBigError<u8>> = invalid_value.try_into();
                assert_eq!(
                    err.unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0000_0111,
                        value_type:  ValueType::IgmpQrv
                    }
                );
            }
            // try_from
            {
                assert_eq!(
                    Qrv::try_from(valid_value).unwrap().value(),
                    valid_value
                );

                assert_eq!(
                    Qrv::try_from(invalid_value).unwrap_err(),
                    ValueTooBigError{
                        actual: invalid_value,
                        max_allowed: 0b0000_0111,
                        value_type:  ValueType::IgmpQrv
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn new_unchecked(valid_value in 0..=0b0000_0111u8) {
            assert_eq!(
                valid_value,
                unsafe {
                    Qrv::new_unchecked(valid_value).value()
                }
            );
        }
    }

    proptest! {
        #[test]
        fn fmt(valid_value in 0..=0b0000_0111u8) {
            assert_eq!(format!("{}", Qrv(valid_value)), format!("{}", valid_value));
        }
    }

    proptest! {
        #[test]
        fn from(valid_value in 0..=0b0000_0111u8) {
            let dscp = Qrv::try_new(valid_value).unwrap();
            let actual: u8 = dscp.into();
            assert_eq!(actual, valid_value);
        }
    }
}
