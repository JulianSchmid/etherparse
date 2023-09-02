use crate::*;

/// In case a route header is present it is also possible
/// to attach a "final destination" header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6RoutingExtensions {
    pub routing: Ipv6RawExtHeader,
    pub final_destination_options: Option<Ipv6RawExtHeader>,
}

impl Ipv6RoutingExtensions {
    /// Minimum length required for routing extension headers in bytes/octets.
    pub const MIN_LEN: usize = Ipv6RawExtHeader::MAX_LEN;

    /// Maximum summed up length of all extension headers in bytes/octets.
    pub const MAX_LEN: usize = Ipv6RawExtHeader::MAX_LEN * 2;

    /// Return the length of the headers in bytes.
    pub fn header_len(&self) -> usize {
        self.routing.header_len()
        + self.final_destination_options.as_ref().map(|h| h.header_len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use crate::test_gens::ipv6_raw_ext_any;

    proptest!{
        #[test]
        fn header_len(
            routing in ipv6_raw_ext_any(),
            final_destination_options in ipv6_raw_ext_any()
        ) {
            // without final dest options
            assert_eq!(
                Ipv6RoutingExtensions{
                    routing: routing.clone(),
                    final_destination_options: None,
                }.header_len(),
                routing.header_len()
            );

            // with final dest options
            assert_eq!(
                Ipv6RoutingExtensions{
                    routing: routing.clone(),
                    final_destination_options: Some(final_destination_options.clone()),
                }.header_len(),
                routing.header_len() + final_destination_options.header_len()
            );
        }
    }
}