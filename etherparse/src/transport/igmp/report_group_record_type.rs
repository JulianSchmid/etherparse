/// Type value within a [`crate::igmp::ReportGroupRecordV3Header`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReportGroupRecordType(pub u8);

impl ReportGroupRecordType {
    /// Indicates that the interface has a filter-mode of INCLUDE
    /// for the specified multicast address. The Source Address \[i\]
    /// fields in this Group Record contain the interface's
    /// source-list for the specified multicast address, if
    /// it is non-empty.
    pub const MODE_IS_INCLUDE: ReportGroupRecordType = ReportGroupRecordType(1);

    /// Indicates that the interface has a filter-mode of EXCLUDE for
    /// the specified multicast address. The Source Address \[i\] fields
    /// in this Group Record contain the interface's source-list for
    /// the specified multicast address, if it is non-empty. An SSM-aware
    /// host SHOULD NOT send a MODE_IS_EXCLUDE record type for multicast
    /// addresses that fall within the SSM address range as they will be
    /// ignored by SSM-aware routers
    pub const MODE_IS_EXCLUDE: ReportGroupRecordType = ReportGroupRecordType(2);

    /// Indicates that the interface has changed to INCLUDE filter-mode for
    /// the specified multicast address. The Source Address \[i\] fields in
    /// this Group Record contain the interface's new source-list for the
    /// specified multicast address, if it is non-empty.
    pub const CHANGE_TO_INCLUDE_MODE: ReportGroupRecordType = ReportGroupRecordType(3);

    /// Indicates that the interface has changed to EXCLUDE filter-mode for
    /// the specified multicast address. The Source Address \[i\] fields in
    /// this Group Record contain the interface's new source-list for the
    /// specified multicast address, if it is non-empty. An SSM-aware host
    /// SHOULD NOT send a CHANGE_TO_EXCLUDE_MODE record type for multicast
    /// addresses that fall within the SSM address range.
    pub const CHANGE_TO_EXCLUDE_MODE: ReportGroupRecordType = ReportGroupRecordType(4);

    /// Indicates that the Source Address \[i\] fields in this Group Record
    /// contain a list of the additional sources that the system wishes to
    /// receive, for packets sent to the specified multicast address. If
    /// the change was to an INCLUDE source-list, these are the addresses
    /// that were added to the list; if the change was to an EXCLUDE
    /// source-list, these are the addresses that were deleted from the list.
    pub const ALLOW_NEW_SOURCES: ReportGroupRecordType = ReportGroupRecordType(5);

    /// Indicates that the Source Address \[i\] fields in this Group Record
    /// contain a list of the sources that the system no longer wishes to
    /// receive, for packets sent to the specified multicast address. If
    /// the change was to an INCLUDE source-list, these are the addresses
    /// that were deleted from the list; if the change was to an EXCLUDE
    /// source-list, these are the addresses that were added to the list.
    pub const BLOCK_OLD_SOURCES: ReportGroupRecordType = ReportGroupRecordType(6);
}
