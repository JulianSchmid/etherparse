use crate::mld;

/// MLD message types specific data (excluding checksum).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MldType {
    /// Multicast Listener Query message type (MLDv1 version, type = 130 and static size).
    MulticastListenerQuery(mld::MulticastListenerQueryType),

    /// Multicast Listener Query message type (MLDv2 version, type = 130 and dynamic size) with sources.
    MulticastListenerQueryWithSources(mld::MulticastListenerQueryWithSourcesHeader),

    /// Multicast Listener Report message type (introduced in MLDv1, type = 131).
    MulticastListenerReportV1(mld::MulticastListenerReportV1Type),

    /// Multicast Listener Report message type (introduced in MLDv2, type = 143 & dynamic size).
    MulticastListenerReportV2(mld::MulticastListenerReportV2Header),

    /// Multicast Listener Done message type (introduced in MLDv1, type = 132).
    MulticastListenerDone(mld::MulticastListenerDoneType),

    /// Unknown type of MLD message.
    Unknown(mld::UnknownHeader),
}
