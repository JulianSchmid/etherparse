use crate::tcp_reassembly::*;

/// Result of passing a packet to a [`TcpReassemblyPool`].
#[derive(Debug)]
pub struct TcpProcessed<'a, Timestamp = (), CustomChannelId = ()> {
    /// Connection the segment was applied to, together with the role of the
    /// segment's sender.
    pub active: Option<(&'a mut TcpConnection<Timestamp, CustomChannelId>, TcpRole)>,

    /// Reason why the packet was applied to no connection.
    pub ignored: Option<TcpIgnoreReason>,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::format;

    #[test]
    fn debug() {
        let processed = TcpProcessed::<(), ()> {
            active: None,
            ignored: Some(TcpIgnoreReason::NoConnection),
        };
        assert_eq!(
            "TcpProcessed { active: None, ignored: Some(NoConnection) }",
            format!("{:?}", processed)
        );
    }
}
