/// Error encountered while iterating over a DNSSL search list.
/// Offsets are measured from the start of the domain-name region, excluding
/// the eight-byte option header. Length fields are described per variant.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum DnsNameReadError {
    /// A label or terminating zero extends beyond the option.
    UnexpectedEnd {
        /// Offset of the label length byte, or the missing terminator.
        offset: usize,
        /// Minimum total region length needed to read this label or terminator.
        required_len: usize,
        /// Available domain-name region length.
        actual_len: usize,
    },
    /// A label length exceeds 63, including unsupported compression encodings.
    InvalidLabelLength {
        /// Offset of the invalid label length byte.
        offset: usize,
        /// Raw label length byte, including any encoding bits.
        value: u8,
    },
    /// A name exceeds 255 encoded bytes, including its terminator.
    NameTooLong {
        /// Offset of the start of the name.
        offset: usize,
        /// Encoded name length reached when the limit was exceeded.
        actual_len: usize,
    },
    /// Padding contains a nonzero byte or exceeds seven bytes.
    InvalidPadding {
        /// Offset of a nonzero or excess padding byte.
        offset: usize,
    },
    /// The search list contains only padding and no domain names.
    EmptySearchList,
}

impl core::fmt::Display for DnsNameReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEnd { offset, required_len, actual_len } => write!(f,
                "DNS name error at offset {offset}: need {required_len} bytes, only {actual_len} available."),
            Self::InvalidLabelLength { offset, value } => write!(f,
                "DNS name error at offset {offset}: label length byte {value} exceeds 63; compression is unsupported."),
            Self::NameTooLong { offset, actual_len } => write!(f,
                "DNS name error at offset {offset}: encoded length {actual_len} exceeds 255 bytes."),
            Self::InvalidPadding { offset } => write!(f,
                "DNS name error at offset {offset}: padding must be at most seven zero bytes."),
            Self::EmptySearchList => f.write_str("DNS name error: search list contains no domain names."),
        }
    }
}

impl core::error::Error for DnsNameReadError {}
