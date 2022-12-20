/// Error when decoding the IPv4 part of a message.
#[derive(Debug, Eq, PartialEq)]
pub enum HeaderError {
    /// Error when the ip header version field is not equal 4. The value is the version that was received.
    UnexpectedVersion{
        /// The unexpected version number that was not 4.
        version_number: u8,
    },
    
    /// Error when the ipv4 internet header length is smaller then the header itself (5).
    HeaderLengthSmallerThanHeader{
        /// The internet header length that was too small.
        ihl: u8,
    },

    /// Error when the total length of the ipv4 packet is smaller then the ipv4 header itself.
    TotalLengthSmallerThanHeader{
        /// The total length value present in the header that was smaller then the header itself.
        total_length: u16,
        /// The minimum expected length based on the 
        min_expected_length: u16,
    },
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        use HeaderError::*;
        match self {
            UnexpectedVersion { version_number } => write!(f, "IPv4 Header Error: Encountered '{}' as IP version number in the IPv4 header (must be '4' in an IPv4 header).", version_number),
            HeaderLengthSmallerThanHeader { ihl } => write!(f, "IPv4 Header Error: The 'internet header length' value '{}' present in the IPv4 header is smaller than the minimum size of an IPv4 header. The minimum allowed value is '5'.", ihl),
            TotalLengthSmallerThanHeader { total_length, min_expected_length } => write!(f, "IPv4 Header Error: The 'total length' value ({} bytes/octets) present in the IPv4 header is smaller then the bytes/octet lenght of the header ({}) itself. 'total length' should describe the bytes/octets count of the IPv4 header and it's payload.", total_length, min_expected_length),
        }
    }
}

impl std::error::Error for HeaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
