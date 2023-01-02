
/// Different kinds of options that can be present in the options part of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionElement {
    /// "No-Operation" option.
    ///
    /// Description from RFC 793:
    ///
    /// This option code may be used between options, for example, to
    /// align the beginning of a subsequent option on a word boundary.
    /// There is no guarantee that senders will use this option, so
    /// receivers must be prepared to process options even if they do
    /// not begin on a word boundary.
    Noop,
    /// "Maximum Segment Size" option.
    ///
    /// Description from RFC 793:
    ///
    /// If this option is present, then it communicates the maximum
    /// receive segment size at the TCP which sends this segment.
    /// This field must only be sent in the initial connection request
    /// (i.e., in segments with the SYN control bit set).  If this
    //// option is not used, any segment size is allowed.
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SelectiveAcknowledgementPermitted,
    SelectiveAcknowledgement((u32, u32), [Option<(u32, u32)>; 3]),
    ///Timestamp & echo (first number is the sender timestamp, the second the echo timestamp)
    Timestamp(u32, u32),
}
