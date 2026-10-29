/// Type value within a [`crate::mld::MulticastAddressRecordHeader`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MulticastAddressRecordType(pub u8);

impl MulticastAddressRecordType {
    /// Indicates that the interface has a filter mode of INCLUDE
    /// for the specified multicast address. The Source Address \[i\]
    /// fields in this Multicast Address Record contain the interface's
    /// source list for the specified multicast address, if it is
    /// non-empty.
    pub const MODE_IS_INCLUDE: MulticastAddressRecordType = MulticastAddressRecordType(1);

    /// Indicates that the interface has a filter mode of EXCLUDE for
    /// the specified multicast address. The Source Address \[i\] fields
    /// in this Multicast Address Record contain the interface's source
    /// list for the specified multicast address, if it is non-empty. An
    /// SSM-aware host SHOULD NOT send a MODE_IS_EXCLUDE record type for
    /// multicast addresses that fall within the SSM address range as
    /// they will be ignored by SSM-aware routers.
    pub const MODE_IS_EXCLUDE: MulticastAddressRecordType = MulticastAddressRecordType(2);

    /// Indicates that the interface has changed to INCLUDE filter mode for
    /// the specified multicast address. The Source Address \[i\] fields in
    /// this Multicast Address Record contain the interface's new source
    /// list for the specified multicast address, if it is non-empty.
    pub const CHANGE_TO_INCLUDE_MODE: MulticastAddressRecordType = MulticastAddressRecordType(3);

    /// Indicates that the interface has changed to EXCLUDE filter mode for
    /// the specified multicast address. The Source Address \[i\] fields in
    /// this Multicast Address Record contain the interface's new source
    /// list for the specified multicast address, if it is non-empty. An
    /// SSM-aware host SHOULD NOT send a CHANGE_TO_EXCLUDE_MODE record type
    /// for multicast addresses that fall within the SSM address range.
    pub const CHANGE_TO_EXCLUDE_MODE: MulticastAddressRecordType = MulticastAddressRecordType(4);

    /// Indicates that the Source Address \[i\] fields in this Multicast
    /// Address Record contain a list of the additional sources that the
    /// node wishes to listen to, for packets sent to the specified
    /// multicast address. If the change was to an INCLUDE source list,
    /// these are the addresses that were added to the list; if the change
    /// was to an EXCLUDE source list, these are the addresses that were
    /// deleted from the list.
    pub const ALLOW_NEW_SOURCES: MulticastAddressRecordType = MulticastAddressRecordType(5);

    /// Indicates that the Source Address \[i\] fields in this Multicast
    /// Address Record contain a list of the sources that the node no
    /// longer wishes to listen to, for packets sent to the specified
    /// multicast address. If the change was to an INCLUDE source list,
    /// these are the addresses that were deleted from the list; if the
    /// change was to an EXCLUDE source list, these are the addresses that
    /// were added to the list.
    pub const BLOCK_OLD_SOURCES: MulticastAddressRecordType = MulticastAddressRecordType(6);
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    /// The record type constants must keep the values assigned by
    /// RFC 9777 section 5.2.12.
    #[test]
    fn constants() {
        assert_eq!(1, MulticastAddressRecordType::MODE_IS_INCLUDE.0);
        assert_eq!(2, MulticastAddressRecordType::MODE_IS_EXCLUDE.0);
        assert_eq!(3, MulticastAddressRecordType::CHANGE_TO_INCLUDE_MODE.0);
        assert_eq!(4, MulticastAddressRecordType::CHANGE_TO_EXCLUDE_MODE.0);
        assert_eq!(5, MulticastAddressRecordType::ALLOW_NEW_SOURCES.0);
        assert_eq!(6, MulticastAddressRecordType::BLOCK_OLD_SOURCES.0);
    }

    /// `Clone`, `Default`, `Debug` & `Ord` must be derived and behave like
    /// the derives on the wrapped `u8`.
    #[test]
    fn derived_traits() {
        let value = MulticastAddressRecordType::MODE_IS_INCLUDE;
        assert_eq!(value, value.clone());
        assert_eq!(
            MulticastAddressRecordType::default(),
            MulticastAddressRecordType(0)
        );
        assert_eq!(
            format!("{:?}", value),
            format!("MulticastAddressRecordType(1)")
        );
        assert!(MulticastAddressRecordType(1) < MulticastAddressRecordType(2));
    }
}
