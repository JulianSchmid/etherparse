use crate::err::ValueTooBigError;

/// Offset of a fragmented IP packet.
/// 
/// [`IpFragOffset`] is an 13 bit unsigned integer indicating the stating
/// position of the payload of a packet relative to the originally
/// fragmented packet payload.
/// 
/// This value can be present in an [`Ipv4Header`] or an [`Ipv6FragmentHeader`].
/// 
/// # Example Usage:
/// 
/// ```
/// use etherparse::IpFragOffset;
/// 
/// // try into
/// {
///     let frag_offset: IpFragOffset = 123.try_into().unwrap();
///     assert_eq!(frag_offset.value(), 123);
/// 
///     // fragment offset can always be converted back to an u16
///     let value: u16 = frag_offset.into();
///     assert_eq!(123, value);
/// }
/// 
/// // via try_new
/// {
///     let frag_offset = IpFragOffset::try_new(123).unwrap();
///     assert_eq!(frag_offset.value(), 123);
/// 
///     // note that only 13 bit numbers are allowed (meaning 
///     // 0b0001_1111_1111_1111 is the maximum allowed value)
///     use etherparse::err::{ValueTooBigError, ValueType};
///     assert_eq!(
///         IpFragOffset::try_new(IpFragOffset::MAX_U16 + 1),
///         Err(ValueTooBigError{
///             actual: IpFragOffset::MAX_U16 + 1,
///             max_allowed: IpFragOffset::MAX_U16,
///             value_type: ValueType::IpFragmentOffset,
///         })
///     );
/// }
/// 
/// // via new_unchecked
/// {
///     // in case you are sure the number does not exceed the max
///     // you can use the unsafe new_unchecked function
///     let frag_offset = unsafe {
///         // please make sure that the value is not greater than IpFragOffset::MAX_U16
///         // before calling this method
///         IpFragOffset::new_unchecked(123)
///     };
///     assert_eq!(frag_offset.value(), 123);
/// }
/// ```
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct IpFragOffset(u16);

impl IpFragOffset {

    /// IpFragOffset with value 0.
    pub const ZERO: IpFragOffset = IpFragOffset(0);

    /// Maximum value value of an IP fragmentation offset.
    pub const MAX_U16: u16 = 0b0001_1111_1111_1111;

    /// Tries to create an [`IpFragOffset`] and checks that the passed value
    /// is smaller or equal than [`IpFragOffset::MAX_U16`] (13 bit unsigned integer).
    /// 
    /// In case the passed value is bigger then what can be represented in an 13 bit
    /// integer an error is returned. Otherwise an `Ok` containing the [`IpFragOffset`].
    /// 
    /// ```
    /// use etherparse::IpFragOffset;
    /// 
    /// let frag_offset = IpFragOffset::try_new(123).unwrap();
    /// assert_eq!(frag_offset.value(), 123);
    /// 
    /// // if a number that can not be represented in an 13 bit integer
    /// // gets passed in an error is returned
    /// use etherparse::err::{ValueTooBigError, ValueType};
    /// assert_eq!(
    ///     IpFragOffset::try_new(IpFragOffset::MAX_U16 + 1),
    ///     Err(ValueTooBigError{
    ///         actual: IpFragOffset::MAX_U16 + 1,
    ///         max_allowed: IpFragOffset::MAX_U16,
    ///         value_type: ValueType::IpFragmentOffset,
    ///     })
    /// );
    /// ```
    /// 
    /// # Safety
    /// 
    /// `value` must be smaller or equal than [`IpFragOffset::MAX_U16`]
    /// otherwise the behaviour of functions or datastructures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const fn try_new(value: u16) -> Result<IpFragOffset, ValueTooBigError<u16>> {
        use crate::err::ValueType::IpFragmentOffset;
        if value <= IpFragOffset::MAX_U16 {
            Ok(IpFragOffset(value))
        } else {
            Err(ValueTooBigError{
                actual: value,
                max_allowed: IpFragOffset::MAX_U16,
                value_type: IpFragmentOffset,
            })
        }
    }

    /// Creates an [`IpFragOffset`] without checking that the value
    /// is smaller or equal than [`IpFragOffset::MAX_U16`] (13 bit unsigned integer).
    /// The caller must gurantee that `value <= IpFragOffset::MAX_U16`.
    /// 
    /// # Safety
    /// 
    /// `value` must be smaller or equal than [`IpFragOffset::MAX_U16`]
    /// otherwise the behaviour of functions or datastructures relying
    /// on this pre-requirement is undefined.
    #[inline]
    pub const unsafe fn new_unchecked(value: u16) -> IpFragOffset {
        debug_assert!(value <= IpFragOffset::MAX_U16);
        IpFragOffset(value)
    }

    /// Returns the underlying `u16` value.
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl core::fmt::Display for IpFragOffset {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<IpFragOffset> for u16 {
    #[inline]
    fn from(value: IpFragOffset) -> Self {
        value.0
    }
}

impl TryFrom<u16> for IpFragOffset {
    type Error = ValueTooBigError<u16>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use crate::err::ValueType::IpFragmentOffset;
        if value <= IpFragOffset::MAX_U16 {
            Ok(IpFragOffset(value))
        } else {
            Err(Self::Error{
                actual: value,
                max_allowed: IpFragOffset::MAX_U16,
                value_type: IpFragmentOffset,
            })
        }
    }
}
