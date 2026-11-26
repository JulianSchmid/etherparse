use crate::tcp_reassembly::*;

/// Result of passing a packet to a [`TcpReassemblyPool`].
#[derive(Debug)]
pub struct TcpProcessed<'a, Timestamp = (), CustomChannelId = ()> {
    /// Connection the segment was applied to, together with the role of the
    /// segment's sender.
    pub active: Option<(&'a mut TcpConnection<Timestamp, CustomChannelId>, TcpRole)>,

    /// Connection ended by the packet, handed over with its remaining bytes.
    ///
    /// Pass it to [`TcpReassemblyPool::recycle`] once you are done with it,
    /// so that its buffers are re-used.
    pub ended: Option<TcpConnection<Timestamp, CustomChannelId>>,

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
            ended: None,
            ignored: Some(TcpIgnoreReason::NoConnection),
        };
        assert_eq!(
            "TcpProcessed { active: None, ended: None, ignored: Some(NoConnection) }",
            format!("{:?}", processed)
        );
    }
}
