mod dest_unreachable_code;
pub use dest_unreachable_code::*;

mod parameter_problem_code;
pub use parameter_problem_code::*;

mod parameter_problem_header;
pub use parameter_problem_header::*;

mod time_exceeded_code;
pub use time_exceeded_code::*;

/// The maximum number of bytes/octets the ICMPv6 part of a packet can contain.
///
/// The value is determined by the maximum value of the "Upper-Layer Packet Length"
/// field. This field is not directly part of the packet but used during the checksum
/// calculation in the pseudo header.
///
/// The "Upper-Layer Packet Length" is represented as an `u32` and defined as
/// "...the Payload Length from the IPv6 header, minus the length of any
/// extension headers present between the IPv6 header and the upper-layer
/// header" (according to RFC 2460 Section 8.1). In other words, the length of the
/// ICMPv6 part of the packet.
///
/// Therefor the maximum size of an ICMPv6 packet is `u32::MAX`.
pub const MAX_ICMPV6_BYTE_LEN: usize = u32::MAX as usize;

/// ICMPv6 type value indicating a "Destination Unreachable" message.
pub const TYPE_DST_UNREACH: u8 = 1;

/// ICMPv6 type value indicating a "Packet Too Big" message.
pub const TYPE_PACKET_TOO_BIG: u8 = 2;

/// ICMPv6 type value indicating a "Time Exceeded" message.
pub const TYPE_TIME_EXCEEDED: u8 = 3;

/// ICMPv6 type value indicating a "Parameter Problem" message.
pub const TYPE_PARAMETER_PROBLEM: u8 = 4;

/// ICMPv6 type value indicating an "Echo Request" message.
pub const TYPE_ECHO_REQUEST: u8 = 128;

/// ICMPv6 type value indicating an "Echo Reply" message.
pub const TYPE_ECHO_REPLY: u8 = 129;

/// ICMPv6 type value indicating a "Multicast Listener Query" message.
pub const TYPE_MULTICAST_LISTENER_QUERY: u8 = 130;

/// ICMPv6 type value indicating a "Multicast Listener Report" message.
pub const TYPE_MULTICAST_LISTENER_REPORT: u8 = 131;

/// ICMPv6 type value indicating a "Multicast Listener Done" message.
pub const TYPE_MULTICAST_LISTENER_REDUCTION: u8 = 132;

/// ICMPv6 type value indicating a "Router Solicitation" message.
pub const TYPE_ROUTER_SOLICITATION: u8 = 133;

/// ICMPv6 type value indicating a "Router Advertisement" message.
pub const TYPE_ROUTER_ADVERTISEMENT: u8 = 134;

/// ICMPv6 type value indicating a "Neighbor Solicitation" message.
pub const TYPE_NEIGHBOR_SOLICITATION: u8 = 135;

/// ICMPv6 type value indicating a "Neighbor Advertisement" message.
pub const TYPE_NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// ICMPv6 type value indicating a "Redirect Message" message.
pub const TYPE_REDIRECT_MESSAGE: u8 = 137;

/// ICMPv6 type value indicating a "Router Renumbering" message.
pub const TYPE_ROUTER_RENUMBERING: u8 = 138;

/// ICMPv6 type value indicating a "Inverse Neighbor Discovery Solicitation" message.
pub const TYPE_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION: u8 = 141;

/// ICMPv6 type value indicating a "Inverse Neighbor Discovery Advertisement" message.
pub const TYPE_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT: u8 = 142;

/// ICMPv6 type value indicating a "Extended Echo Request" message.
pub const TYPE_EXT_ECHO_REQUEST: u8 = 160;

/// ICMPv6 type value indicating a "Extended Echo Reply" message.
pub const TYPE_EXT_ECHO_REPLY: u8 = 161;

/// ICMPv6 destination unreachable code for "no route to destination".
pub const CODE_DST_UNREACH_NO_ROUTE: u8 = 0;

/// ICMPv6 destination unreachable code for "communication with
/// destination administratively prohibited".
pub const CODE_DST_UNREACH_PROHIBITED: u8 = 1;

/// ICMPv6 destination unreachable code for "beyond scope of source address".
pub const CODE_DST_UNREACH_BEYOND_SCOPE: u8 = 2;

/// ICMPv6 destination unreachable code for "address unreachable".
pub const CODE_DST_UNREACH_ADDR: u8 = 3;

/// ICMPv6 destination unreachable code for "port unreachable".
pub const CODE_DST_UNREACH_PORT: u8 = 4;

/// ICMPv6 destination unreachable code for "source address failed ingress/egress policy".
pub const CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY: u8 = 5;

/// ICMPv6 destination unreachable code for "reject route to destination".
pub const CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST: u8 = 6;

/// ICMPv6 time exceeded code for "hop limit exceeded in transit"
pub const CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED: u8 = 0;

/// ICMPv6 time exceeded code for "fragment reassembly time exceeded"
pub const CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED: u8 = 1;

/// ICMPv6 parameter problem code for "erroneous header field encountered" (from [RFC 4443](https://tools.ietf.org/html/rfc4443)).
pub const CODE_PARAM_PROBLEM_ERR_HEADER_FIELD: u8 = 0;

/// ICMPv6 parameter problem code for "unrecognized Next Header type encountered" (from [RFC 4443](https://tools.ietf.org/html/rfc4443)).
pub const CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER: u8 = 1;

/// ICMPv6 parameter problem code for "unrecognized IPv6 option encountered" (from [RFC 4443](https://tools.ietf.org/html/rfc4443)).
pub const CODE_PARAM_PROBLEM_UNRECOG_IPV6_OPTION: u8 = 2;

/// ICMPv6 parameter problem code for "IPv6 First Fragment has incomplete IPv6 Header Chain" (from [RFC 7112](https://tools.ietf.org/html/rfc7112)).
pub const CODE_PARAM_PROBLEM_IPV6_FIRST_FRAG_INCOMP_HEADER_CHAIN: u8 = 3;

/// ICMPv6 parameter problem code for "SR Upper-layer Header Error" (from [RFC 8754](https://tools.ietf.org/html/rfc8754)).
pub const CODE_PARAM_PROBLEM_SR_UPPER_LAYER_HEADER_ERROR: u8 = 4;

/// ICMPv6 parameter problem code for "Unrecognized Next Header type encountered by intermediate node" (from [RFC 8883](https://tools.ietf.org/html/rfc8883)).
pub const CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER_BY_INTERMEDIATE_NODE: u8 = 5;

/// ICMPv6 parameter problem code for "Extension header too big" (from [RFC 8883](https://tools.ietf.org/html/rfc8883)).
pub const CODE_PARAM_PROBLEM_EXT_HEADER_TOO_BIG: u8 = 6;

/// ICMPv6 parameter problem code for "Extension header chain too long" (from [RFC 8883](https://tools.ietf.org/html/rfc8883)).
pub const CODE_PARAM_PROBLEM_EXT_HEADER_CHAIN_TOO_LONG: u8 = 7;

/// ICMPv6 parameter problem code for "Too many extension headers" (from [RFC 8883](https://tools.ietf.org/html/rfc8883)).
pub const CODE_PARAM_PROBLEM_TOO_MANY_EXT_HEADERS: u8 = 8;

/// ICMPv6 parameter problem code for "Too many options in extension header" (from [RFC 8883](https://tools.ietf.org/html/rfc8883)).
pub const CODE_PARAM_PROBLEM_TOO_MANY_OPTIONS_EXT_HEADER: u8 = 9;

/// ICMPv6 parameter problem code for "Option too big" (from [RFC 8883](https://tools.ietf.org/html/rfc8883)).
pub const CODE_PARAM_PROBLEM_OPTION_TOO_BIG: u8 = 10;
