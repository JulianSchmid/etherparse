use crate::tcp_reassembly::*;

/// Reason why a [`crate::tcp_reassembly::TcpConnection`] ended.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpConnectionEnd {
    /// Both endpoints sent a FIN, and both FINs were ACKed.
    Finished,

    /// An endpoint reset the connection with an RST.
    ///
    /// Only RSTs that the receiver can accept count: their sequence number
    /// lies from the receiver's ACK up to one receive window after the bytes
    /// sent (RFC 9293). Other RSTs, e.g. blindly injected ones, are ignored
    /// and counted in
    /// [`crate::tcp_reassembly::TcpStreamStatus::out_of_window_segments`]
    /// of the sender's stream.
    Reset {
        /// Role of the endpoint that sent the RST.
        by: TcpRole,
    },
}

#[cfg(test)]
mod test {
    use super::*;
    use core::hash::{Hash, Hasher};
    use std::format;

    #[test]
    fn derived_traits() {
        // copy & clone
        {
            let a = TcpConnectionEnd::Reset {
                by: TcpRole::Responder,
            };
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
            assert_ne!(TcpConnectionEnd::Finished, a);
            assert_ne!(
                TcpConnectionEnd::Reset {
                    by: TcpRole::Initiator
                },
                a
            );
        }

        // debug
        {
            assert_eq!("Finished", format!("{:?}", TcpConnectionEnd::Finished));
            assert_eq!(
                "Reset { by: Initiator }",
                format!(
                    "{:?}",
                    TcpConnectionEnd::Reset {
                        by: TcpRole::Initiator
                    }
                )
            );
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let hash = |end: TcpConnectionEnd| {
                let mut hasher = DefaultHasher::new();
                end.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(
                hash(TcpConnectionEnd::Finished),
                hash(TcpConnectionEnd::Finished)
            );
        }
    }
}
