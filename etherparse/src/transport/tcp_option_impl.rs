#[deprecated(since = "0.10.1", note = "Please use tcp_option::KIND_END instead")]
/// Deprecated please use [tcp_option::KIND_END] instead.
pub const TCP_OPTION_ID_END: u8 = 0;

#[deprecated(since = "0.10.1", note = "Please use tcp_option::KIND_NOOP instead")]
/// Deprecated please use [tcp_option::KIND_NOOP] instead.
pub const TCP_OPTION_ID_NOP: u8 = 1;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_MAXIMUM_SEGMENT_SIZE instead"
)]
/// Deprecated please use [tcp_option::KIND_MAXIMUM_SEGMENT_SIZE] instead.
pub const TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE: u8 = 2;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_WINDOW_SCALE instead"
)]
/// Deprecated please use [tcp_option::KIND_WINDOW_SCALE] instead.
pub const TCP_OPTION_ID_WINDOW_SCALE: u8 = 3;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_SELECTIVE_ACK_PERMITTED instead"
)]
/// Deprecated please use [tcp_option::KIND_SELECTIVE_ACK_PERMITTED] instead.
pub const TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED: u8 = 4;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_SELECTIVE_ACK instead"
)]
/// Deprecated please use [tcp_option::KIND_SELECTIVE_ACK] instead.
pub const TCP_OPTION_ID_SELECTIVE_ACK: u8 = 5;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_TIMESTAMP instead"
)]
/// Deprecated please use [tcp_option::KIND_TIMESTAMP] instead.
pub const TCP_OPTION_ID_TIMESTAMP: u8 = 8;

/// Module containing the constants for tcp options (id number & sizes).
pub mod tcp_option {
    /// `u8` identifying the "end of options list" in the tcp option.
    pub const KIND_END: u8 = 0;
    /// `u8` identifying a "no operation" tcp option.
    pub const KIND_NOOP: u8 = 1;
    /// `u8` identifying a "maximum segment size" tcp option.
    pub const KIND_MAXIMUM_SEGMENT_SIZE: u8 = 2;
    /// `u8` identifying a "window scaling" tcp option.
    pub const KIND_WINDOW_SCALE: u8 = 3;
    /// `u8` identifying a "selective acknowledgement permitted" tcp option.
    pub const KIND_SELECTIVE_ACK_PERMITTED: u8 = 4;
    /// `u8` identifying a "selective acknowledgement" tcp option.
    pub const KIND_SELECTIVE_ACK: u8 = 5;
    /// `u8` identifying a "timestamp and echo of previous timestamp" tcp option.
    pub const KIND_TIMESTAMP: u8 = 8;
    /// `u8` identifying an "echo" tcp option (obsoleted by [`KIND_TIMESTAMP`]).
    pub const KIND_ECHO: u8 = 6;
    /// `u8` identifying an "echo reply" tcp option (obsoleted by [`KIND_TIMESTAMP`]).
    pub const KIND_ECHO_REPLY: u8 = 7;
    /// `u8` identifying a "partial order connection permitted" tcp option (obsolete).
    pub const KIND_PARTIAL_ORDER_CONNECTION_PERMITTED: u8 = 9;
    /// `u8` identifying a "partial order service profile" tcp option (obsolete).
    pub const KIND_PARTIAL_ORDER_SERVICE_PROFILE: u8 = 10;
    /// `u8` identifying a "CC" tcp option (obsolete).
    pub const KIND_CC: u8 = 11;
    /// `u8` identifying a "CC.NEW" tcp option (obsolete).
    pub const KIND_CC_NEW: u8 = 12;
    /// `u8` identifying a "CC.ECHO" tcp option (obsolete).
    pub const KIND_CC_ECHO: u8 = 13;
    /// `u8` identifying a "TCP alternate checksum request" tcp option (obsolete).
    pub const KIND_ALTERNATE_CHECKSUM_REQUEST: u8 = 14;
    /// `u8` identifying a "TCP alternate checksum data" tcp option (obsolete).
    pub const KIND_ALTERNATE_CHECKSUM_DATA: u8 = 15;
    /// `u8` identifying a "Skeeter" tcp option.
    pub const KIND_SKEETER: u8 = 16;
    /// `u8` identifying a "Bubba" tcp option.
    pub const KIND_BUBBA: u8 = 17;
    /// `u8` identifying a "trailer checksum" tcp option.
    pub const KIND_TRAILER_CHECKSUM: u8 = 18;
    /// `u8` identifying a "MD5 signature" tcp option (RFC 2385, obsoleted by [`KIND_AUTHENTICATION`]).
    pub const KIND_MD5_SIGNATURE: u8 = 19;
    /// `u8` identifying a "SCPS capabilities" tcp option.
    pub const KIND_SCPS_CAPABILITIES: u8 = 20;
    /// `u8` identifying a "selective negative acknowledgements" tcp option.
    pub const KIND_SELECTIVE_NEGATIVE_ACK: u8 = 21;
    /// `u8` identifying a "record boundaries" tcp option.
    pub const KIND_RECORD_BOUNDARIES: u8 = 22;
    /// `u8` identifying a "corruption experienced" tcp option.
    pub const KIND_CORRUPTION_EXPERIENCED: u8 = 23;
    /// `u8` identifying a "SNAP" tcp option.
    pub const KIND_SNAP: u8 = 24;
    /// `u8` identifying a "TCP compression filter" tcp option.
    pub const KIND_COMPRESSION_FILTER: u8 = 26;
    /// `u8` identifying a "quick-start response" tcp option (RFC 4782).
    pub const KIND_QUICK_START_RESPONSE: u8 = 27;
    /// `u8` identifying a "user timeout" tcp option (RFC 5482).
    pub const KIND_USER_TIMEOUT: u8 = 28;
    /// `u8` identifying a "TCP authentication option" (TCP-AO, RFC 5925).
    pub const KIND_AUTHENTICATION: u8 = 29;
    /// `u8` identifying a "multipath TCP" tcp option (MPTCP, RFC 8684).
    pub const KIND_MULTIPATH: u8 = 30;
    /// `u8` identifying a "TCP fast open cookie" tcp option (RFC 7413).
    pub const KIND_FAST_OPEN_COOKIE: u8 = 34;
    /// `u8` identifying an "encryption negotiation" tcp option (TCP-ENO, RFC 8547).
    pub const KIND_ENCRYPTION_NEGOTIATION: u8 = 69;
    /// `u8` identifying an "accurate ECN order 0" tcp option (AccECN0, RFC 9768).
    pub const KIND_ACCURATE_ECN_ORDER_0: u8 = 172;
    /// `u8` identifying an "accurate ECN order 1" tcp option (AccECN1, RFC 9768).
    pub const KIND_ACCURATE_ECN_ORDER_1: u8 = 174;
    /// `u8` identifying a "RFC3692-style experiment 1" tcp option (RFC 4727).
    pub const KIND_EXPERIMENT_1: u8 = 253;
    /// `u8` identifying a "RFC3692-style experiment 2" tcp option (RFC 4727).
    pub const KIND_EXPERIMENT_2: u8 = 254;
    /// Length in octets/bytes of the "end" tcp option (includes kind value).
    pub const LEN_END: u8 = 1;
    /// Length in octets/bytes of the "no operation" tcp option (includes kind value).
    pub const LEN_NOOP: u8 = 1;
    /// Length in octets/bytes of the "maximum segment size" tcp option (includes kind value).
    pub const LEN_MAXIMUM_SEGMENT_SIZE: u8 = 4;
    /// Length in octets/bytes of the "window scaling" tcp option (includes kind value).
    pub const LEN_WINDOW_SCALE: u8 = 3;
    /// Length in octets/bytes of the "selective acknowledgement permitted" tcp option (includes kind value).
    pub const LEN_SELECTIVE_ACK_PERMITTED: u8 = 2;
    /// Length in octets/bytes of the "timestamp and echo of previous timestamp" tcp option (includes kind value).
    pub const LEN_TIMESTAMP: u8 = 10;
    /// Length in octets/bytes of the "echo" tcp option (includes kind value).
    pub const LEN_ECHO: u8 = 6;
    /// Length in octets/bytes of the "echo reply" tcp option (includes kind value).
    pub const LEN_ECHO_REPLY: u8 = 6;
    /// Length in octets/bytes of the "partial order connection permitted" tcp option (includes kind value).
    pub const LEN_PARTIAL_ORDER_CONNECTION_PERMITTED: u8 = 2;
    /// Length in octets/bytes of the "partial order service profile" tcp option (includes kind value).
    pub const LEN_PARTIAL_ORDER_SERVICE_PROFILE: u8 = 3;
    /// Length in octets/bytes of the "TCP alternate checksum request" tcp option (includes kind value).
    pub const LEN_ALTERNATE_CHECKSUM_REQUEST: u8 = 3;
    /// Length in octets/bytes of the "trailer checksum" tcp option (includes kind value).
    pub const LEN_TRAILER_CHECKSUM: u8 = 3;
    /// Length in octets/bytes of the "MD5 signature" tcp option (includes kind value).
    pub const LEN_MD5_SIGNATURE: u8 = 18;
    /// Length in octets/bytes of the "quick-start response" tcp option (includes kind value).
    pub const LEN_QUICK_START_RESPONSE: u8 = 8;
    /// Length in octets/bytes of the "user timeout" tcp option (includes kind value).
    pub const LEN_USER_TIMEOUT: u8 = 4;

    /// Returns the meaning registered by IANA for a tcp option kind or `None`
    /// if the kind is unassigned or reserved.
    ///
    /// Source: <https://www.iana.org/assignments/tcp-parameters#tcp-parameters-1>
    ///
    /// ```
    /// use etherparse::tcp_option;
    ///
    /// assert_eq!(Some("Multipath TCP (MPTCP)"), tcp_option::kind_name(tcp_option::KIND_MULTIPATH));
    /// assert_eq!(None, tcp_option::kind_name(99));
    /// ```
    pub const fn kind_name(kind: u8) -> Option<&'static str> {
        Some(match kind {
            KIND_END => "End of Option List",
            KIND_NOOP => "No-Operation",
            KIND_MAXIMUM_SEGMENT_SIZE => "Maximum Segment Size",
            KIND_WINDOW_SCALE => "Window Scale",
            KIND_SELECTIVE_ACK_PERMITTED => "SACK Permitted",
            KIND_SELECTIVE_ACK => "SACK",
            KIND_ECHO => "Echo (obsoleted by option 8)",
            KIND_ECHO_REPLY => "Echo Reply (obsoleted by option 8)",
            KIND_TIMESTAMP => "Timestamps",
            KIND_PARTIAL_ORDER_CONNECTION_PERMITTED => {
                "Partial Order Connection Permitted (obsolete)"
            }
            KIND_PARTIAL_ORDER_SERVICE_PROFILE => "Partial Order Service Profile (obsolete)",
            KIND_CC => "CC (obsolete)",
            KIND_CC_NEW => "CC.NEW (obsolete)",
            KIND_CC_ECHO => "CC.ECHO (obsolete)",
            KIND_ALTERNATE_CHECKSUM_REQUEST => "TCP Alternate Checksum Request (obsolete)",
            KIND_ALTERNATE_CHECKSUM_DATA => "TCP Alternate Checksum Data (obsolete)",
            KIND_SKEETER => "Skeeter",
            KIND_BUBBA => "Bubba",
            KIND_TRAILER_CHECKSUM => "Trailer Checksum Option",
            KIND_MD5_SIGNATURE => "MD5 Signature Option (obsoleted by option 29)",
            KIND_SCPS_CAPABILITIES => "SCPS Capabilities",
            KIND_SELECTIVE_NEGATIVE_ACK => "Selective Negative Acknowledgements",
            KIND_RECORD_BOUNDARIES => "Record Boundaries",
            KIND_CORRUPTION_EXPERIENCED => "Corruption experienced",
            KIND_SNAP => "SNAP",
            KIND_COMPRESSION_FILTER => "TCP Compression Filter",
            KIND_QUICK_START_RESPONSE => "Quick-Start Response",
            KIND_USER_TIMEOUT => "User Timeout Option",
            KIND_AUTHENTICATION => "TCP Authentication Option (TCP-AO)",
            KIND_MULTIPATH => "Multipath TCP (MPTCP)",
            KIND_FAST_OPEN_COOKIE => "TCP Fast Open Cookie",
            KIND_ENCRYPTION_NEGOTIATION => "Encryption Negotiation (TCP-ENO)",
            KIND_ACCURATE_ECN_ORDER_0 => "Accurate ECN Order 0 (AccECN0)",
            KIND_ACCURATE_ECN_ORDER_1 => "Accurate ECN Order 1 (AccECN1)",
            KIND_EXPERIMENT_1 => "RFC3692-style Experiment 1",
            KIND_EXPERIMENT_2 => "RFC3692-style Experiment 2",
            _ => return None,
        })
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn kind_name() {
            assert_eq!(Some("End of Option List"), super::kind_name(KIND_END));
            assert_eq!(
                Some("Maximum Segment Size"),
                super::kind_name(KIND_MAXIMUM_SEGMENT_SIZE)
            );
            assert_eq!(
                Some("TCP Fast Open Cookie"),
                super::kind_name(KIND_FAST_OPEN_COOKIE)
            );
            assert_eq!(
                Some("RFC3692-style Experiment 2"),
                super::kind_name(KIND_EXPERIMENT_2)
            );
            let assigned = (0..=255u8)
                .filter(|k| super::kind_name(*k).is_some())
                .count();
            assert_eq!(36, assigned);
            for unassigned in [25, 31, 33, 35, 68, 70, 71, 76, 79, 171, 173, 175, 252, 255] {
                assert_eq!(None, super::kind_name(unassigned), "kind {unassigned}");
            }
        }
    }
}
