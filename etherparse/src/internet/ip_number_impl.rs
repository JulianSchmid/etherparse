/// This type has been deprecated please use [IpNumber] instead.
///
/// IPv6 headers have a field called `traffic_class` which has nothing
/// to do this enum. This unlucky coincedence got even the developer
/// of this library confused enough to write that the next header number
/// should be written into the `traffic_class` field instead of the
/// `next_header` field.
///
/// To avoid such confusions in the future the enum has been renamed
/// to [IpNumber], which also closer to the name
/// "Assigned Internet Protocol Numbers" used on iana.org .
#[deprecated(since = "0.10.1", note = "Please use the type IpNumber instead")]
pub type IpTrafficClass = IpNumber;

/// Identifiers for the next_header field in ipv6 headers and protocol field in ipv4 headers.
///
/// You can access the underlying `u8` value by using `.0` and any `u8`
/// can be converted to an `IpNumber`:
/// 
/// ```
/// use etherparse::IpNumber;
///
/// assert_eq!(IpNumber::TCP.0, 6);
/// assert_eq!(IpNumber::TCP, IpNumber(6));
/// 
/// // convert to IpNumber using the from & into trait
/// let ip_num: IpNumber = 6.into();
/// assert_eq!(IpNumber::TCP, ip_num);
/// 
/// // convert to u8 using the from & into trait
/// let num: u8 = IpNumber::TCP.into();
/// assert_eq!(6, num);
/// ```
/// 
/// The constants are also defined in the `ip_number` module so they can
/// be used without the need to write `IpNumber::` in front of them:
/// 
/// ```
/// use etherparse::{ip_number::TCP, IpNumber};
/// 
/// assert_eq!(TCP, IpNumber::TCP);
/// ```
///
/// The list original values were copied from
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[derive(PartialEq, Eq, Clone, Copy, Hash, Ord, PartialOrd)]
pub struct IpNumber(pub u8);

impl IpNumber {
    /// IPv6 Hop-by-Hop Option \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_HEADER_HOP_BY_HOP: IpNumber = Self(0);
    /// Internet Control Message \[[RFC792](https://datatracker.ietf.org/doc/html/rfc792)\]
    pub const ICMP: IpNumber = Self(1);
    /// Internet Group Management \[[RFC1112](https://datatracker.ietf.org/doc/html/rfc1112)\]
    pub const IGMP: IpNumber = Self(2);
    /// Gateway-to-Gateway \[[RFC823](https://datatracker.ietf.org/doc/html/rfc823)\]
    pub const GGP: IpNumber = Self(3);
    /// IPv4 encapsulation \[[RFC2003](https://datatracker.ietf.org/doc/html/rfc2003)\]
    pub const IPV4: IpNumber = Self(4);
    /// Stream \[[RFC1190](https://datatracker.ietf.org/doc/html/rfc1190)\] \[[RFC1819](https://datatracker.ietf.org/doc/html/rfc1819)\]
    pub const STREAM: IpNumber = Self(5);
    /// Transmission Control \[[RFC793](https://datatracker.ietf.org/doc/html/rfc793)\]
    pub const TCP: IpNumber = Self(6);
    /// CBT \[Tony_Ballardie\]
    pub const CBT: IpNumber = Self(7);
    /// Exterior Gateway Protocol \[[RFC888](https://datatracker.ietf.org/doc/html/rfc888)\] \[David_Mills\]
    pub const EGP: IpNumber = Self(8);
    /// any private interior gateway (used by Cisco for their IGRP) \[Internet_Assigned_Numbers_Authority\]
    pub const IGP: IpNumber = Self(9);
    /// BBN RCC Monitoring \[Steve_Chipman\]
    pub const BBN_RCC_MON: IpNumber = Self(10);
    /// Network Voice Protocol \[[RFC741](https://datatracker.ietf.org/doc/html/rfc741)\]\[Steve_Casner\]
    pub const NVP_II: IpNumber = Self(11);
    /// PUP
    pub const PUP: IpNumber = Self(12);
    /// ARGUS (deprecated) \[Robert_W_Scheifler\]
    pub const ARGUS: IpNumber = Self(13);
    /// EMCON \[mystery contact\]
    pub const EMCON: IpNumber = Self(14);
    /// Cross Net Debugger \[Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.\]\[Jack_Haverty\]
    pub const XNET: IpNumber = Self(15);
    /// Chaos \[J_Noel_Chiappa\]
    pub const CHAOS: IpNumber = Self(16);
    /// User Datagram \[[RFC768](https://datatracker.ietf.org/doc/html/rfc768)\]\[Jon_Postel\]
    pub const UDP: IpNumber = Self(17);
    /// Multiplexing \[Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.\]\[Jon_Postel\]
    pub const MUX: IpNumber = Self(18);
    /// DCN Measurement Subsystems \[David_Mills\]
    pub const DCN_MEAS: IpNumber = Self(19);
    /// Host Monitoring \[[RFC869](https://datatracker.ietf.org/doc/html/rfc869)\]\[Bob_Hinden\]
    pub const HMP: IpNumber = Self(20);
    /// Packet Radio Measurement \[Zaw_Sing_Su\]
    pub const PRM: IpNumber = Self(21);
    /// XEROX NS IDP
    pub const XNS_IDP: IpNumber = Self(22);
    /// Trunk-1 \[Barry_Boehm\]
    pub const TRUNK1: IpNumber = Self(23);
    /// Trunk-2 \[Barry_Boehm\]
    pub const TRUNK2: IpNumber = Self(24);
    /// Leaf-1 \[Barry_Boehm\]
    pub const LEAF1: IpNumber = Self(25);
    /// Leaf-2 \[Barry_Boehm\]
    pub const LEAF2: IpNumber = Self(26);
    /// Reliable Data Protocol \[[RFC908](https://datatracker.ietf.org/doc/html/rfc908)\] \[Bob_Hinden\]
    pub const RDP: IpNumber = Self(27);
    /// Internet Reliable Transaction \[[RFC938](https://datatracker.ietf.org/doc/html/rfc938)\] \[Trudy_Miller\]
    pub const IRTP: IpNumber = Self(28);
    /// ISO Transport Protocol Class 4 \[[RFC905](https://datatracker.ietf.org/doc/html/rfc905)\] \[<mystery contact>\]
    pub const ISO_TP4: IpNumber = Self(29);
    /// Bulk Data Transfer Protocol \[[RFC969](https://datatracker.ietf.org/doc/html/rfc969)\] \[David_Clark\]
    pub const NET_BLT: IpNumber = Self(30);
    /// MFE Network Services Protocol \[Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.\] \[Barry_Howard\]
    pub const MFE_NSP: IpNumber = Self(31);
    /// MERIT Internodal Protocol \[Hans_Werner_Braun\]
    pub const MERIT_INP: IpNumber = Self(32);
    /// Datagram Congestion Control Protocol \[[RFC4340](https://datatracker.ietf.org/doc/html/rfc4340)\]
    pub const DCCP: IpNumber = Self(33);
    /// Third Party Connect Protocol \[Stuart_A_Friedberg\]
    pub const THIRD_PARTY_CONNECT_PROTOCOL: IpNumber = Self(34);
    /// Inter-Domain Policy Routing Protocol \[Martha_Steenstrup\]
    pub const IDPR: IpNumber = Self(35);
    /// XTP \[Greg_Chesson\]
    pub const XTP: IpNumber = Self(36);
    /// Datagram Delivery Protocol \[Wesley_Craig\]
    pub const DDP: IpNumber = Self(37);
    /// IDPR Control Message Transport Proto \[Martha_Steenstrup\]
    pub const IDPR_CMTP: IpNumber = Self(38);
    /// TP++ Transport Protocol \[Dirk_Fromhein\]
    pub const TP_PLUS_PLUS: IpNumber = Self(39);
    /// IL Transport Protocol \[Dave_Presotto\]
    pub const IL: IpNumber = Self(40);
    /// IPv6 encapsulation \[[RFC2473](https://datatracker.ietf.org/doc/html/rfc2473)\]
    pub const IPV6: IpNumber = Self(41);
    /// Source Demand Routing Protocol \[Deborah_Estrin\]
    pub const SDRP: IpNumber = Self(42);
    /// Routing Header for IPv6 \[Steve_Deering\]
    pub const IPV6_ROUTE_HEADER: IpNumber = Self(43);
    /// Fragment Header for IPv6 \[Steve_Deering\]
    pub const IPV6_FRAGMENTATION_HEADER: IpNumber = Self(44);
    /// Inter-Domain Routing Protocol \[Sue_Hares\]
    pub const IDRP: IpNumber = Self(45);
    /// Reservation Protocol \[[RFC2205](https://datatracker.ietf.org/doc/html/rfc2205)\]\[[RFC3209](https://datatracker.ietf.org/doc/html/rfc3209)\]\[Bob_Braden\]
    pub const RSVP: IpNumber = Self(46);
    /// Generic Routing Encapsulation \[[RFC2784](https://datatracker.ietf.org/doc/html/rfc2784)\]\[Tony_Li\]
    pub const GRE: IpNumber = Self(47);
    /// Dynamic Source Routing Protocol \[[RFC4728](https://datatracker.ietf.org/doc/html/rfc4728)\]
    pub const DSR: IpNumber = Self(48);
    /// BNA \[Gary Salamon\]
    pub const BNA: IpNumber = Self(49);
    /// Encapsulating Security Payload \[[RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)\]
    pub const ENCAPSULATING_SECURITY_PAYLOAD: IpNumber = Self(50);
    /// Authentication Header \[[RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)\]
    pub const AUTHENTICATION_HEADER: IpNumber = Self(51);
    /// Integrated Net Layer Security  TUBA \[K_Robert_Glenn\]
    pub const INLSP: IpNumber = Self(52);
    /// IP with Encryption (deprecated) \[John_Ioannidis\]
    pub const SWIPE: IpNumber = Self(53);
    /// NBMA Address Resolution Protocol \[[RFC1735](https://datatracker.ietf.org/doc/html/rfc1735)\]
    pub const NARP: IpNumber = Self(54);
    /// IP Mobility \[Charlie_Perkins\]
    pub const MOBILE: IpNumber = Self(55);
    /// Transport Layer Security Protocol using Kryptonet key management \[Christer_Oberg\]
    pub const TLSP: IpNumber = Self(56);
    /// SKIP \[Tom_Markson\]
    pub const SKIP: IpNumber = Self(57);
    /// ICMP for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_ICMP: IpNumber = Self(58);
    /// No Next Header for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_NO_NEXT_HEADER: IpNumber = Self(59);
    /// Destination Options for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_DESTINATION_OPTIONS: IpNumber = Self(60);
    /// any host internal protocol \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_HOST_INTERNAL_PROTOCOL: IpNumber = Self(61);
    /// CFTP \[Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.\]\[Harry_Forsdick\]
    pub const CFTP: IpNumber = Self(62);
    /// any local network \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_LOCAL_NETWORK: IpNumber = Self(63);
    /// SATNET and Backroom EXPAK \[Steven_Blumenthal\]
    pub const SAT_EXPAK: IpNumber = Self(64);
    /// Kryptolan \[Paul Liu\]
    pub const KRYTOLAN: IpNumber = Self(65);
    /// MIT Remote Virtual Disk Protocol \[Michael_Greenwald\]
    pub const RVD: IpNumber = Self(66);
    /// Internet Pluribus Packet Core \[Steven_Blumenthal\]
    pub const IPPC: IpNumber = Self(67);
    /// any distributed file system \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_DISTRIBUTED_FILE_SYSTEM: IpNumber = Self(68);
    /// SATNET Monitoring \[Steven_Blumenthal\]
    pub const SAT_MON: IpNumber = Self(69);
    /// VISA Protocol \[Gene_Tsudik\]
    pub const VISA: IpNumber = Self(70);
    /// Internet Packet Core Utility \[Steven_Blumenthal\]
    pub const IPCV: IpNumber = Self(71);
    /// Computer Protocol Network Executive \[David Mittnacht\]
    pub const CPNX: IpNumber = Self(72);
    /// Computer Protocol Heart Beat \[David Mittnacht\]
    pub const CPHB: IpNumber = Self(73);
    /// Wang Span Network \[Victor Dafoulas\]
    pub const WSN: IpNumber = Self(74);
    /// Packet Video Protocol \[Steve_Casner\]
    pub const PVP: IpNumber = Self(75);
    /// Backroom SATNET Monitoring \[Steven_Blumenthal\]
    pub const BR_SAT_MON: IpNumber = Self(76);
    /// SUN ND PROTOCOL-Temporary \[William_Melohn\]
    pub const SUN_ND: IpNumber = Self(77);
    /// WIDEBAND Monitoring \[Steven_Blumenthal\]
    pub const WB_MON: IpNumber = Self(78);
    /// WIDEBAND EXPAK \[Steven_Blumenthal\]
    pub const WB_EXPAK: IpNumber = Self(79);
    /// ISO Internet Protocol \[Marshall_T_Rose\]
    pub const ISO_IP: IpNumber = Self(80);
    /// VMTP \[Dave_Cheriton\]
    pub const VMTP: IpNumber = Self(81);
    /// SECURE-VMTP \[Dave_Cheriton\]
    pub const SECURE_VMTP: IpNumber = Self(82);
    /// VINES \[Brian Horn\]
    pub const VINES: IpNumber = Self(83);
    /// Transaction Transport Protocol or Internet Protocol Traffic Manager \[Jim_Stevens\]
    pub const TTP_OR_IPTM: IpNumber = Self(84);
    /// NSFNET-IGP \[Hans_Werner_Braun\]
    pub const NSFNET_IGP: IpNumber = Self(85);
    /// Dissimilar Gateway Protocol \[M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.\]\[Mike_Little\]
    pub const DGP: IpNumber = Self(86);
    /// TCF \[Guillermo_A_Loyola\]
    pub const TCF: IpNumber = Self(87);
    /// EIGRP \[[RFC7868](https://datatracker.ietf.org/doc/html/rfc7868)\]
    pub const EIGRP: IpNumber = Self(88);
    /// OSPFIGP \[[RFC1583](https://datatracker.ietf.org/doc/html/rfc1583)\]\[[RFC2328](https://datatracker.ietf.org/doc/html/rfc2328)\]\[[RFC5340](https://datatracker.ietf.org/doc/html/rfc5340)\]\[John_Moy\]
    pub const OSPFIGP: IpNumber = Self(89);
    /// Sprite RPC Protocol \[Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.\]\[Bruce Willins\]
    pub const SPRITE_RPC: IpNumber = Self(90);
    /// Locus Address Resolution Protocol \[Brian Horn\]
    pub const LARP: IpNumber = Self(91);
    /// Multicast Transport Protocol \[Susie_Armstrong\]
    pub const MTP: IpNumber = Self(92);
    /// AX.25 Frames \[Brian_Kantor\]
    pub const AX25: IpNumber = Self(93);
    /// IP-within-IP Encapsulation Protocol \[John_Ioannidis\]
    pub const IPIP: IpNumber = Self(94);
    /// Mobile Internetworking Control Pro. (deprecated) \[John_Ioannidis\]
    pub const MICP: IpNumber = Self(95);
    /// Semaphore Communications Sec. Pro. \[Howard_Hart\]
    pub const SCC_SP: IpNumber = Self(96);
    /// Ethernet-within-IP Encapsulation \[[RFC3378](https://datatracker.ietf.org/doc/html/rfc3378)\]
    pub const ETHER_IP: IpNumber = Self(97);
    /// Encapsulation Header \[[RFC1241](https://datatracker.ietf.org/doc/html/rfc1241)\]\[Robert_Woodburn\]
    pub const ENCAP: IpNumber = Self(98);
    /// GMTP \[\[RXB5\]\]
    pub const GMTP: IpNumber = Self(100);
    /// Ipsilon Flow Management Protocol \[Bob_Hinden\]\[November 1995, 1997.\]
    pub const IFMP: IpNumber = Self(101);
    /// PNNI over IP \[Ross_Callon\]
    pub const PNNI: IpNumber = Self(102);
    /// Protocol Independent Multicast \[[RFC7761](https://datatracker.ietf.org/doc/html/rfc7761)\]\[Dino_Farinacci\]
    pub const PIM: IpNumber = Self(103);
    /// ARIS \[Nancy_Feldman\]
    pub const ARIS: IpNumber = Self(104);
    /// SCPS \[Robert_Durst\]
    pub const SCPS: IpNumber = Self(105);
    /// QNX \[Michael_Hunter\]
    pub const QNX: IpNumber = Self(106);
    /// Active Networks \[Bob_Braden\]
    pub const ACTIVE_NETWORKS: IpNumber = Self(107);
    /// IP Payload Compression Protocol \[[RFC2393](https://datatracker.ietf.org/doc/html/rfc2393)\]
    pub const IP_COMP: IpNumber = Self(108);
    /// Sitara Networks Protocol \[Manickam_R_Sridhar\]
    pub const SITRA_NETWORKS_PROTOCOL: IpNumber = Self(109);
    /// Compaq Peer Protocol \[Victor_Volpe\]
    pub const COMPAQ_PEER: IpNumber = Self(110);
    /// IPX in IP \[CJ_Lee\]
    pub const IPX_IN_IP: IpNumber = Self(111);
    /// Virtual Router Redundancy Protocol \[[RFC5798](https://datatracker.ietf.org/doc/html/rfc5798)\]
    pub const VRRP: IpNumber = Self(112);
    /// PGM Reliable Transport Protocol \[Tony_Speakman\]
    pub const PGM: IpNumber = Self(113);
    /// any 0-hop protocol \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_ZERO_HOP_PROTOCOL: IpNumber = Self(114);
    /// Layer Two Tunneling Protocol \[[RFC3931](https://datatracker.ietf.org/doc/html/rfc3931)\]\[Bernard_Aboba\]
    pub const LAYER2_TUNNELING_PROTOCOL: IpNumber = Self(115);
    /// D-II Data Exchange (DDX) \[John_Worley\]
    pub const DDX: IpNumber = Self(116);
    /// Interactive Agent Transfer Protocol \[John_Murphy\]
    pub const IATP: IpNumber = Self(117);
    /// Schedule Transfer Protocol \[Jean_Michel_Pittet\]
    pub const STP: IpNumber = Self(118);
    /// SpectraLink Radio Protocol \[Mark_Hamilton\]
    pub const SRP: IpNumber = Self(119);
    /// UTI \[Peter_Lothberg\]
    pub const UTI: IpNumber = Self(120);
    /// Simple Message Protocol \[Leif_Ekblad\]
    pub const SIMPLE_MESSAGE_PROTOCOL: IpNumber = Self(121);
    /// Simple Multicast Protocol (deprecated) \[Jon_Crowcroft\]\[draft-perlman-simple-multicast\]
    pub const SM: IpNumber = Self(122);
    /// Performance Transparency Protocol \[Michael_Welzl\]
    pub const PTP: IpNumber = Self(123);
    /// ISIS over IPv4 \[Tony_Przygienda\]
    pub const ISIS_OVER_IPV4: IpNumber = Self(124);
    /// FIRE \[Criag_Partridge\]
    pub const FIRE: IpNumber = Self(125);
    /// Combat Radio Transport Protocol \[Robert_Sautter\]
    pub const CRTP: IpNumber = Self(126);
    /// Combat Radio User Datagram \[Robert_Sautter\]
    pub const CRUDP: IpNumber = Self(127);
    /// SSCOPMCE \[Kurt_Waber\]
    pub const SSCOPMCE: IpNumber = Self(128);
    /// IPLT \[\[Hollbach\]\]
    pub const IPLT: IpNumber = Self(129);
    /// Secure Packet Shield \[Bill_McIntosh\]
    pub const SPS: IpNumber = Self(130);
    /// Private IP Encapsulation within IP \[Bernhard_Petri\]
    pub const PIPE: IpNumber = Self(131);
    /// Stream Control Transmission Protocol \[Randall_R_Stewart\]
    pub const SCTP: IpNumber = Self(132);
    /// Fibre Channel \[Murali_Rajagopal\]\[[RFC6172](https://datatracker.ietf.org/doc/html/rfc6172)\]
    pub const FC: IpNumber = Self(133);
    /// RSVP-E2E-IGNORE \[[RFC3175](https://datatracker.ietf.org/doc/html/rfc3175)\]
    pub const RSVP_E2E_IGNORE: IpNumber = Self(134);
    /// MobilityHeader \[[RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)\]
    pub const MOBILITY_HEADER: IpNumber = Self(135);
    /// UDPLite \[[RFC3828](https://datatracker.ietf.org/doc/html/rfc3828)\]
    pub const UDP_LITE: IpNumber = Self(136);
    /// \[[RFC4023](https://datatracker.ietf.org/doc/html/rfc4023)\]
    pub const MPLS_IN_IP: IpNumber = Self(137);
    /// MANET Protocols \[[RFC5498](https://datatracker.ietf.org/doc/html/rfc5498)\]
    pub const MANET: IpNumber = Self(138);
    /// Host Identity Protocol \[[RFC7401](https://datatracker.ietf.org/doc/html/rfc7401)\]
    pub const HIP: IpNumber = Self(139);
    /// Shim6 Protocol \[[RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)\]
    pub const SHIM6: IpNumber = Self(140);
    /// Wrapped Encapsulating Security Payload \[[RFC5840](https://datatracker.ietf.org/doc/html/rfc5840)\]
    pub const WESP: IpNumber = Self(141);
    /// Robust Header Compression \[[RFC5858](https://datatracker.ietf.org/doc/html/rfc5858)\]
    pub const ROHC: IpNumber = Self(142);
    /// Use for experimentation and testing
    pub const EXPERIMENTAL_AND_TESTING_0: IpNumber = Self(253);
    /// Use for experimentation and testing
    pub const EXPERIMENTAL_AND_TESTING_1: IpNumber = Self(254);
}

impl IpNumber {
    /// Returns true if the given number is the internet number of an IPV6 extension header.
    pub fn is_ipv6_ext_header_value(self) -> bool {
        use crate::ip_number::*;
        matches!(
            self,
            IPV6_HOP_BY_HOP
                | IPV6_ROUTE
                | IPV6_FRAG
                | ENCAP_SEC
                | AUTH
                | IPV6_DEST_OPTIONS
                | MOBILITY
                | HIP
                | SHIM6
                | EXP0
                | EXP1
        )
    }
}

impl Default for IpNumber {
    fn default() -> Self {
        // 255 chosen as it is not used by any
        // protocol and is reserved.
        Self(255)
    }
}

impl From<u8> for IpNumber {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

impl From<IpNumber> for u8 {
    fn from(val: IpNumber) -> Self {
        val.0
    }
}

impl core::fmt::Debug for IpNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::IPV6_HEADER_HOP_BY_HOP => write!(f, "Ipv6HeaderHopByHop({})", self.0),
            Self::ICMP => write!(f, "ICMP({})", self.0),
            Self::IGMP => write!(f, "IGMP({})", self.0),
            Self::GGP => write!(f, "GGP({})", self.0),
            Self::IPV4 => write!(f, "Ipv4({})", self.0),
            Self::STREAM => write!(f, "Stream({})", self.0),
            Self::TCP => write!(f, "TCP({})", self.0),
            Self::UDP => write!(f, "UDP({})", self.0),
            Self::IPV6 => write!(f, "Ipv6({})", self.0),
            Self::IPV6_ROUTE_HEADER => write!(f, "Ipv6RouteHeader({})", self.0),
            Self::IPV6_FRAGMENTATION_HEADER => write!(f, "Ipv6FragmentationHeader({})", self.0),
            Self::ENCAPSULATING_SECURITY_PAYLOAD => {
                write!(f, "EncapsulatingSecurityPayload({})", self.0)
            }
            Self::AUTHENTICATION_HEADER => write!(f, "AuthenticationHeader({})", self.0),
            Self::IPV6_ICMP => write!(f, "ICMPv6({})", self.0),
            Self::IPV6_DESTINATION_OPTIONS => write!(f, "Ipv6DestinationOptions({})", self.0),
            Self::MOBILITY_HEADER => write!(f, "MobilityHeader({})", self.0),
            Self::HIP => write!(f, "HIP({})", self.0),
            Self::SHIM6 => write!(f, "SHIM6({})", self.0),
            _ => write!(f, "IpNumber({})", self.0),
        }
    }
}

/// Constants for the most used ip protocol numbers for easy importing
/// (e.g. `use ip_number::*;`).
///
/// The constants only exist for convenience so you can import them
/// (`use ip_number::*`) without a need to write `IpNumber::` in front
/// of every constant. 
/// 
/// You can access the underlying `u8` value by using `.0` and any `u8`
/// can be converted to an `IpNumber`:
/// 
/// ```
/// use etherparse::{ip_number::TCP, IpNumber};
///
/// assert_eq!(TCP.0, 6);
/// assert_eq!(TCP, IpNumber(6));
/// let num: IpNumber = 6.into();
/// assert_eq!(TCP, num);
/// ```
///
/// The list original values were copied from
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
pub mod ip_number {
    use crate::IpNumber;

    /// IPv6 Hop-by-Hop Option \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_HOP_BY_HOP: IpNumber = IpNumber::IPV6_HEADER_HOP_BY_HOP; // 0
    /// IPv6 Hop-by-Hop Option \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_HEADER_HOP_BY_HOP: IpNumber = IpNumber::IPV6_HEADER_HOP_BY_HOP; // 0
    /// Internet Control Message \[[RFC792](https://datatracker.ietf.org/doc/html/rfc792)\]
    pub const ICMP: IpNumber = IpNumber::ICMP; // 1
    /// Internet Group Management \[[RFC1112](https://datatracker.ietf.org/doc/html/rfc1112)\]
    pub const IGMP: IpNumber = IpNumber::IGMP; // 2
    /// Gateway-to-Gateway \[[RFC823](https://datatracker.ietf.org/doc/html/rfc823)\]
    pub const GGP: IpNumber = IpNumber::GGP; // 3
    /// IPv4 encapsulation \[[RFC2003](https://datatracker.ietf.org/doc/html/rfc2003)\]
    pub const IPV4: IpNumber = IpNumber::IPV4; // 4
    /// Stream \[[RFC1190](https://datatracker.ietf.org/doc/html/rfc1190)\] \[[RFC1819](https://datatracker.ietf.org/doc/html/rfc1819)\]
    pub const STREAM: IpNumber = IpNumber::STREAM; // 5
    /// Transmission Control \[[RFC793](https://datatracker.ietf.org/doc/html/rfc793)\]
    pub const TCP: IpNumber = IpNumber::TCP; // 6
    /// CBT \[Tony_Ballardie\]
    pub const CBT: IpNumber = IpNumber::CBT; // 7
    /// Exterior Gateway Protocol \[[RFC888](https://datatracker.ietf.org/doc/html/rfc888)\] \[David_Mills\]
    pub const EGP: IpNumber = IpNumber::EGP; // 8
    /// any private interior gateway (used by Cisco for their IGRP) \[Internet_Assigned_Numbers_Authority\]
    pub const IGP: IpNumber = IpNumber::IGP; // 9
    /// BBN RCC Monitoring \[Steve_Chipman\]
    pub const BBN_RCC_MON: IpNumber = IpNumber::BBN_RCC_MON; // 10
    /// Network Voice Protocol \[[RFC741](https://datatracker.ietf.org/doc/html/rfc741)\]\[Steve_Casner\]
    pub const NVP_II: IpNumber = IpNumber::NVP_II; // 11
    /// PUP
    pub const PUP: IpNumber = IpNumber::PUP; // 12
    /// ARGUS (deprecated) \[Robert_W_Scheifler\]
    pub const ARGUS: IpNumber = IpNumber::ARGUS; // 13
    /// EMCON \[mystery contact\]
    pub const EMCON: IpNumber = IpNumber::EMCON; // 14
    /// Cross Net Debugger \[Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.\]\[Jack_Haverty\]
    pub const XNET: IpNumber = IpNumber::XNET; // 15
    /// Chaos \[J_Noel_Chiappa\]
    pub const CHAOS: IpNumber = IpNumber::CHAOS; // 16
    /// User Datagram \[[RFC768](https://datatracker.ietf.org/doc/html/rfc768)\] \[Jon_Postel\]
    pub const UDP: IpNumber = IpNumber::UDP; // 17
    /// Multiplexing \[Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.\]\[Jon_Postel\]
    pub const MUX: IpNumber = IpNumber::MUX; // 18
    /// DCN Measurement Subsystems \[David_Mills\]
    pub const DCN_MEAS: IpNumber = IpNumber::DCN_MEAS; // 19
    /// Host Monitoring \[[RFC869](https://datatracker.ietf.org/doc/html/rfc869)\]\[Bob_Hinden\]
    pub const HMP: IpNumber = IpNumber::HMP; // 20
    /// Packet Radio Measurement \[Zaw_Sing_Su\]
    pub const PRM: IpNumber = IpNumber::PRM; // 21
    /// XEROX NS IDP
    pub const XNS_IDP: IpNumber = IpNumber::XNS_IDP; // 22
    /// Trunk-1 \[Barry_Boehm\]
    pub const TRUNK1: IpNumber = IpNumber::TRUNK1; // 23
    /// Trunk-2 \[Barry_Boehm\]
    pub const TRUNK2: IpNumber = IpNumber::TRUNK2; // 24
    /// Leaf-1 \[Barry_Boehm\]
    pub const LEAF1: IpNumber = IpNumber::LEAF1; // 25
    /// Leaf-2 \[Barry_Boehm\]
    pub const LEAF2: IpNumber = IpNumber::LEAF2; // 26
    /// Reliable Data Protocol \[[RFC908](https://datatracker.ietf.org/doc/html/rfc908)\] \[Bob_Hinden\]
    pub const RDP: IpNumber = IpNumber::RDP; // 27
    /// Internet Reliable Transaction \[[RFC938](https://datatracker.ietf.org/doc/html/rfc938)\] \[Trudy_Miller\]
    pub const IRTP: IpNumber = IpNumber::IRTP; // 28
    /// ISO Transport Protocol Class 4 \[[RFC905](https://datatracker.ietf.org/doc/html/rfc905)\] \[<mystery contact>\]
    pub const ISO_TP4: IpNumber = IpNumber::ISO_TP4; // 29
    /// Bulk Data Transfer Protocol \[[RFC969](https://datatracker.ietf.org/doc/html/rfc969)\] \[David_Clark\]
    pub const NET_BLT: IpNumber = IpNumber::NET_BLT; // 30
    /// MFE Network Services Protocol \[Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.\] \[Barry_Howard\]
    pub const MFE_NSP: IpNumber = IpNumber::MFE_NSP; // 31
    /// MERIT Internodal Protocol \[Hans_Werner_Braun\]
    pub const MERIT_INP: IpNumber = IpNumber::MERIT_INP; // 32
    /// Datagram Congestion Control Protocol \[[RFC4340](https://datatracker.ietf.org/doc/html/rfc4340)\]
    pub const DCCP: IpNumber = IpNumber::DCCP; // 33
    /// Third Party Connect Protocol \[Stuart_A_Friedberg\]
    pub const THIRD_PARTY_CONNECT_PROTOCOL: IpNumber = IpNumber::THIRD_PARTY_CONNECT_PROTOCOL; // 34
    /// Inter-Domain Policy Routing Protocol \[Martha_Steenstrup\]
    pub const IDPR: IpNumber = IpNumber::IDPR; // 35
    /// XTP \[Greg_Chesson\]
    pub const XTP: IpNumber = IpNumber::XTP; // 36
    /// Datagram Delivery Protocol \[Wesley_Craig\]
    pub const DDP: IpNumber = IpNumber::DDP; // 37
    /// IDPR Control Message Transport Proto \[Martha_Steenstrup\]
    pub const IDPR_CMTP: IpNumber = IpNumber::IDPR_CMTP; // 38
    /// TP++ Transport Protocol \[Dirk_Fromhein\]
    pub const TP_PLUS_PLUS: IpNumber = IpNumber::TP_PLUS_PLUS; // 39
    /// IL Transport Protocol \[Dave_Presotto\]
    pub const IL: IpNumber = IpNumber::IL; // 40
    /// IPv6 encapsulation \[[RFC2473](https://datatracker.ietf.org/doc/html/rfc2473)\]
    pub const IPV6: IpNumber = IpNumber::IPV6; // 41
    /// Source Demand Routing Protocol \[Deborah_Estrin\]
    pub const SDRP: IpNumber = IpNumber::SDRP; // 42
    /// Routing Header for IPv6 \[Steve_Deering\]
    pub const IPV6_ROUTE_HEADER: IpNumber = IpNumber::IPV6_ROUTE_HEADER; // 43
    /// Routing Header for IPv6 \[Steve_Deering\]
    pub const IPV6_ROUTE: IpNumber = IpNumber::IPV6_ROUTE_HEADER; // 43
    /// Fragment Header for IPv6 \[Steve_Deering\]
    pub const IPV6_FRAGMENTATION_HEADER: IpNumber = IpNumber::IPV6_FRAGMENTATION_HEADER; // 44
    /// Fragment Header for IPv6 \[Steve_Deering\]
    pub const IPV6_FRAG: IpNumber = IpNumber::IPV6_FRAGMENTATION_HEADER; // 44
    /// Inter-Domain Routing Protocol \[Sue_Hares\]
    pub const IDRP: IpNumber = IpNumber::IDRP; // 45
    /// Reservation Protocol \[[RFC2205](https://datatracker.ietf.org/doc/html/rfc2205)\]\[[RFC3209](https://datatracker.ietf.org/doc/html/rfc3209)\]\[Bob_Braden\]
    pub const RSVP: IpNumber = IpNumber::RSVP; // 46
    /// Generic Routing Encapsulation \[[RFC2784](https://datatracker.ietf.org/doc/html/rfc2784)\]\[Tony_Li\]
    pub const GRE: IpNumber = IpNumber::GRE; // 47
    /// Dynamic Source Routing Protocol \[[RFC4728](https://datatracker.ietf.org/doc/html/rfc4728)\]
    pub const DSR: IpNumber = IpNumber::DSR; // 48
    /// BNA \[Gary Salamon\]
    pub const BNA: IpNumber = IpNumber::BNA; // 49
    /// Encapsulating Security Payload \[[RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)\]
    pub const ENCAP_SEC: IpNumber = IpNumber::ENCAPSULATING_SECURITY_PAYLOAD; // 50
    /// Encapsulating Security Payload \[[RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)\]
    pub const ENCAPSULATING_SECURITY_PAYLOAD: IpNumber = IpNumber::ENCAPSULATING_SECURITY_PAYLOAD; // 50
    /// Authentication Header \[[RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)\]
    pub const AUTH: IpNumber = IpNumber::AUTHENTICATION_HEADER; // 51
    /// Authentication Header \[[RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)\]
    pub const AUTHENTICATION_HEADER: IpNumber = IpNumber::AUTHENTICATION_HEADER; // 51
    /// Integrated Net Layer Security  TUBA \[K_Robert_Glenn\]
    pub const INLSP: IpNumber = IpNumber::INLSP; // 52
    /// IP with Encryption (deprecated) \[John_Ioannidis\]
    pub const SWIPE: IpNumber = IpNumber::SWIPE; // 53
    /// NBMA Address Resolution Protocol \[[RFC1735](https://datatracker.ietf.org/doc/html/rfc1735)\]
    pub const NARP: IpNumber = IpNumber::NARP; // 54
    /// IP Mobility \[Charlie_Perkins\]
    pub const MOBILE: IpNumber = IpNumber::MOBILE; // 55
    /// Transport Layer Security Protocol using Kryptonet key management \[Christer_Oberg\]
    pub const TLSP: IpNumber = IpNumber::TLSP; // 56
    /// SKIP \[Tom_Markson\]
    pub const SKIP: IpNumber = IpNumber::SKIP; // 57
    /// IPv6 ICMP next-header type \[[RFC4443](https://datatracker.ietf.org/doc/html/rfc4443)\]
    pub const IPV6_ICMP: IpNumber = IpNumber::IPV6_ICMP; // 58
    /// No Next Header for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_NO_NEXT_HEADER: IpNumber = IpNumber::IPV6_NO_NEXT_HEADER; // 59
    /// Destination Options for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_DEST_OPTIONS: IpNumber = IpNumber::IPV6_DESTINATION_OPTIONS; // 60
    /// Destination Options for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_DESTINATION_OPTIONS: IpNumber = IpNumber::IPV6_DESTINATION_OPTIONS; // 60
    /// any host internal protocol \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_HOST_INTERNAL_PROTOCOL: IpNumber = IpNumber::ANY_HOST_INTERNAL_PROTOCOL; // 61
    /// CFTP \[Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.\]\[Harry_Forsdick\]
    pub const CFTP: IpNumber = IpNumber::CFTP; // 62
    /// any local network \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_LOCAL_NETWORK: IpNumber = IpNumber::ANY_LOCAL_NETWORK; // 63
    /// SATNET and Backroom EXPAK \[Steven_Blumenthal\]
    pub const SAT_EXPAK: IpNumber = IpNumber::SAT_EXPAK; // 64
    /// Kryptolan \[Paul Liu\]
    pub const KRYTOLAN: IpNumber = IpNumber::KRYTOLAN; // 65
    /// MIT Remote Virtual Disk Protocol \[Michael_Greenwald\]
    pub const RVD: IpNumber = IpNumber::RVD; // 66
    /// Internet Pluribus Packet Core \[Steven_Blumenthal\]
    pub const IPPC: IpNumber = IpNumber::IPPC; // 67
    /// any distributed file system \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_DISTRIBUTED_FILE_SYSTEM: IpNumber = IpNumber::ANY_DISTRIBUTED_FILE_SYSTEM; // 68
    /// SATNET Monitoring \[Steven_Blumenthal\]
    pub const SAT_MON: IpNumber = IpNumber::SAT_MON; // 69
    /// VISA Protocol \[Gene_Tsudik\]
    pub const VISA: IpNumber = IpNumber::VISA; // 70
    /// Internet Packet Core Utility \[Steven_Blumenthal\]
    pub const IPCV: IpNumber = IpNumber::IPCV; // 71
    /// Computer Protocol Network Executive \[David Mittnacht\]
    pub const CPNX: IpNumber = IpNumber::CPNX; // 72
    /// Computer Protocol Heart Beat \[David Mittnacht\]
    pub const CPHB: IpNumber = IpNumber::CPHB; // 73
    /// Wang Span Network \[Victor Dafoulas\]
    pub const WSN: IpNumber = IpNumber::WSN; // 74
    /// Packet Video Protocol \[Steve_Casner\]
    pub const PVP: IpNumber = IpNumber::PVP; // 75
    /// Backroom SATNET Monitoring \[Steven_Blumenthal\]
    pub const BR_SAT_MON: IpNumber = IpNumber::BR_SAT_MON; // 76
    /// SUN ND PROTOCOL-Temporary \[William_Melohn\]
    pub const SUN_ND: IpNumber = IpNumber::SUN_ND; // 77
    /// WIDEBAND Monitoring \[Steven_Blumenthal\]
    pub const WB_MON: IpNumber = IpNumber::WB_MON; // 78
    /// WIDEBAND EXPAK \[Steven_Blumenthal\]
    pub const WB_EXPAK: IpNumber = IpNumber::WB_EXPAK; // 79
    /// ISO Internet Protocol \[Marshall_T_Rose\]
    pub const ISO_IP: IpNumber = IpNumber::ISO_IP; // 80
    /// VMTP \[Dave_Cheriton\]
    pub const VMTP: IpNumber = IpNumber::VMTP; // 81
    /// SECURE-VMTP \[Dave_Cheriton\]
    pub const SECURE_VMTP: IpNumber = IpNumber::SECURE_VMTP; // 82
    /// VINES \[Brian Horn\]
    pub const VINES: IpNumber = IpNumber::VINES; // 83
    /// Transaction Transport Protocol or Internet Protocol Traffic Manager \[Jim_Stevens\]
    pub const TTP_OR_IPTM: IpNumber = IpNumber::TTP_OR_IPTM; // 84
    /// NSFNET-IGP \[Hans_Werner_Braun\]
    pub const NSFNET_IGP: IpNumber = IpNumber::NSFNET_IGP; // 85
    /// Dissimilar Gateway Protocol \[M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.\]\[Mike_Little\]
    pub const DGP: IpNumber = IpNumber::DGP; // 86
    /// TCF \[Guillermo_A_Loyola\]
    pub const TCF: IpNumber = IpNumber::TCF; // 87
    /// EIGRP \[[RFC7868](https://datatracker.ietf.org/doc/html/rfc7868)\]
    pub const EIGRP: IpNumber = IpNumber::EIGRP; // 88
    /// OSPFIGP \[[RFC1583](https://datatracker.ietf.org/doc/html/rfc1583)\]\[[RFC2328](https://datatracker.ietf.org/doc/html/rfc2328)\]\[[RFC5340](https://datatracker.ietf.org/doc/html/rfc5340)\]\[John_Moy\]
    pub const OSPFIGP: IpNumber = IpNumber::OSPFIGP; // 89
    /// Sprite RPC Protocol \[Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.\]\[Bruce Willins\]
    pub const SPRITE_RPC: IpNumber = IpNumber::SPRITE_RPC; // 90
    /// Locus Address Resolution Protocol \[Brian Horn\]
    pub const LARP: IpNumber = IpNumber::LARP; // 91
    /// Multicast Transport Protocol \[Susie_Armstrong\]
    pub const MTP: IpNumber = IpNumber::MTP; // 92
    /// AX.25 Frames \[Brian_Kantor\]
    pub const AX25: IpNumber = IpNumber::AX25; // 93
    /// IP-within-IP Encapsulation Protocol \[John_Ioannidis\]
    pub const IPIP: IpNumber = IpNumber::IPIP; // 94
    /// Mobile Internetworking Control Pro. (deprecated) \[John_Ioannidis\]
    pub const MICP: IpNumber = IpNumber::MICP; // 95
    /// Semaphore Communications Sec. Pro. \[Howard_Hart\]
    pub const SCC_SP: IpNumber = IpNumber::SCC_SP; // 96
    /// Ethernet-within-IP Encapsulation \[[RFC3378](https://datatracker.ietf.org/doc/html/rfc3378)\]
    pub const ETHER_IP: IpNumber = IpNumber::ETHER_IP; // 97
    /// Encapsulation Header \[[RFC1241](https://datatracker.ietf.org/doc/html/rfc1241)\]\[Robert_Woodburn\]
    pub const ENCAP: IpNumber = IpNumber::ENCAP; // 98
    /// GMTP \[\[RXB5\]\]
    pub const GMTP: IpNumber = IpNumber::GMTP; // 100
    /// Ipsilon Flow Management Protocol \[Bob_Hinden\]\[November 1995, 1997.\]
    pub const IFMP: IpNumber = IpNumber::IFMP; // 101
    /// PNNI over IP \[Ross_Callon\]
    pub const PNNI: IpNumber = IpNumber::PNNI; // 102
    /// Protocol Independent Multicast \[[RFC7761](https://datatracker.ietf.org/doc/html/rfc7761)\]\[Dino_Farinacci\]
    pub const PIM: IpNumber = IpNumber::PIM; // 103
    /// ARIS \[Nancy_Feldman\]
    pub const ARIS: IpNumber = IpNumber::ARIS; // 104
    /// SCPS \[Robert_Durst\]
    pub const SCPS: IpNumber = IpNumber::SCPS; // 105
    /// QNX \[Michael_Hunter\]
    pub const QNX: IpNumber = IpNumber::QNX; // 106
    /// Active Networks \[Bob_Braden\]
    pub const ACTIVE_NETWORKS: IpNumber = IpNumber::ACTIVE_NETWORKS; // 107
    /// IP Payload Compression Protocol \[[RFC2393](https://datatracker.ietf.org/doc/html/rfc2393)\]
    pub const IP_COMP: IpNumber = IpNumber::IP_COMP; // 108
    /// Sitara Networks Protocol \[Manickam_R_Sridhar\]
    pub const SITRA_NETWORKS_PROTOCOL: IpNumber = IpNumber::SITRA_NETWORKS_PROTOCOL; // 109
    /// Compaq Peer Protocol \[Victor_Volpe\]
    pub const COMPAQ_PEER: IpNumber = IpNumber::COMPAQ_PEER; // 110
    /// IPX in IP \[CJ_Lee\]
    pub const IPX_IN_IP: IpNumber = IpNumber::IPX_IN_IP; // 111
    /// Virtual Router Redundancy Protocol \[[RFC5798](https://datatracker.ietf.org/doc/html/rfc5798)\]
    pub const VRRP: IpNumber = IpNumber::VRRP; // 112
    /// PGM Reliable Transport Protocol \[Tony_Speakman\]
    pub const PGM: IpNumber = IpNumber::PGM; // 113
    /// any 0-hop protocol \[Internet_Assigned_Numbers_Authority\]
    pub const ANY_ZERO_HOP_PROTOCOL: IpNumber = IpNumber::ANY_ZERO_HOP_PROTOCOL; // 114
    /// Layer Two Tunneling Protocol \[[RFC3931](https://datatracker.ietf.org/doc/html/rfc3931)\]\[Bernard_Aboba\]
    pub const LAYER2_TUNNELING_PROTOCOL: IpNumber = IpNumber::LAYER2_TUNNELING_PROTOCOL; // 115
    /// D-II Data Exchange (DDX) \[John_Worley\]
    pub const DDX: IpNumber = IpNumber::DDX; // 116
    /// Interactive Agent Transfer Protocol \[John_Murphy\]
    pub const IATP: IpNumber = IpNumber::IATP; // 117
    /// Schedule Transfer Protocol \[Jean_Michel_Pittet\]
    pub const STP: IpNumber = IpNumber::STP; // 118
    /// SpectraLink Radio Protocol \[Mark_Hamilton\]
    pub const SRP: IpNumber = IpNumber::SRP; // 119
    /// UTI \[Peter_Lothberg\]
    pub const UTI: IpNumber = IpNumber::UTI; // 120
    /// Simple Message Protocol \[Leif_Ekblad\]
    pub const SIMPLE_MESSAGE_PROTOCOL: IpNumber = IpNumber::SIMPLE_MESSAGE_PROTOCOL; // 121
    /// Simple Multicast Protocol (deprecated) \[Jon_Crowcroft\]\[draft-perlman-simple-multicast\]
    pub const SM: IpNumber = IpNumber::SM; // 122
    /// Performance Transparency Protocol \[Michael_Welzl\]
    pub const PTP: IpNumber = IpNumber::PTP; // 123
    /// ISIS over IPv4 \[Tony_Przygienda\]
    pub const ISIS_OVER_IPV4: IpNumber = IpNumber::ISIS_OVER_IPV4; // 124
    /// FIRE \[Criag_Partridge\]
    pub const FIRE: IpNumber = IpNumber::FIRE; // 125
    /// Combat Radio Transport Protocol \[Robert_Sautter\]
    pub const CRTP: IpNumber = IpNumber::CRTP; // 126
    /// Combat Radio User Datagram \[Robert_Sautter\]
    pub const CRUDP: IpNumber = IpNumber::CRUDP; // 127
    /// SSCOPMCE \[Kurt_Waber\]
    pub const SSCOPMCE: IpNumber = IpNumber::SSCOPMCE; // 128
    /// IPLT \[\[Hollbach\]\]
    pub const IPLT: IpNumber = IpNumber::IPLT; // 129
    /// Secure Packet Shield \[Bill_McIntosh\]
    pub const SPS: IpNumber = IpNumber::SPS; // 130
    /// Private IP Encapsulation within IP \[Bernhard_Petri\]
    pub const PIPE: IpNumber = IpNumber::PIPE; // 131
    /// Stream Control Transmission Protocol \[Randall_R_Stewart\]
    pub const SCTP: IpNumber = IpNumber::SCTP; // 132
    /// Fibre Channel \[Murali_Rajagopal\]\[[RFC6172](https://datatracker.ietf.org/doc/html/rfc6172)\]
    pub const FC: IpNumber = IpNumber::FC; // 133
    /// RSVP-E2E-IGNORE \[[RFC3175](https://datatracker.ietf.org/doc/html/rfc3175)\]
    pub const RSVP_E2E_IGNORE: IpNumber = IpNumber::RSVP_E2E_IGNORE; // 134
    /// MobilityHeader \[[RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)\]
    pub const MOBILITY: IpNumber = IpNumber::MOBILITY_HEADER; // 135
    /// MobilityHeader \[[RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)\]
    pub const MOBILITY_HEADER: IpNumber = IpNumber::MOBILITY_HEADER; // 135
    /// UDPLite \[[RFC3828](https://datatracker.ietf.org/doc/html/rfc3828)\]
    pub const UDP_LITE: IpNumber = IpNumber::UDP_LITE; // 136
    /// \[[RFC4023](https://datatracker.ietf.org/doc/html/rfc4023)\]
    pub const MPLS_IN_IP: IpNumber = IpNumber::MPLS_IN_IP; // 137
    /// MANET Protocols \[[RFC5498](https://datatracker.ietf.org/doc/html/rfc5498)\]
    pub const MANET: IpNumber = IpNumber::MANET; // 138
    /// Host Identity Protocol \[[RFC7401](https://datatracker.ietf.org/doc/html/rfc7401)\]
    pub const HIP: IpNumber = IpNumber::HIP; // 139
    /// Shim6 Protocol \[[RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)\]
    pub const SHIM6: IpNumber = IpNumber::SHIM6; // 140
    /// Wrapped Encapsulating Security Payload \[[RFC5840](https://datatracker.ietf.org/doc/html/rfc5840)\]
    pub const WESP: IpNumber = IpNumber::WESP; // 141
    /// Robust Header Compression \[[RFC5858](https://datatracker.ietf.org/doc/html/rfc5858)\]
    pub const ROHC: IpNumber = IpNumber::ROHC; // 142
    /// Use for experimentation and testing
    pub const EXP0: IpNumber = IpNumber::EXPERIMENTAL_AND_TESTING_0; // 253
    /// Use for experimentation and testing
    pub const EXPERIMENTAL_AND_TESTING_0: IpNumber = IpNumber::EXPERIMENTAL_AND_TESTING_0; // 253
    /// Use for experimentation and testing
    pub const EXP1: IpNumber = IpNumber::EXPERIMENTAL_AND_TESTING_1; // 254
    /// Use for experimentation and testing
    pub const EXPERIMENTAL_AND_TESTING_1: IpNumber = IpNumber::EXPERIMENTAL_AND_TESTING_1; // 254
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        cmp::Ordering,
        hash::{Hash, Hasher},
    };
    use std::{collections::hash_map::DefaultHasher, format};

    #[test]
    fn is_ipv6_ext_header_value() {
        use crate::ip_number::*;
        use crate::IpNumber;
        let ext_ids = [
            IPV6_HOP_BY_HOP,
            IPV6_ROUTE,
            IPV6_FRAG,
            ENCAP_SEC,
            AUTH,
            IPV6_DEST_OPTIONS,
            MOBILITY,
            HIP,
            SHIM6,
            EXP0,
            EXP1,
        ];

        for i in 0..std::u8::MAX {
            assert_eq!(ext_ids.contains(&IpNumber(i)), IpNumber(i).is_ipv6_ext_header_value());
        }
    }

    #[test]
    fn ip_number_eq_check() {
        use crate::ip_number::*;
        use crate::IpNumber;
        let pairs = &[
            (IPV6_HOP_BY_HOP, IpNumber::IPV6_HEADER_HOP_BY_HOP),
            (IPV6_HEADER_HOP_BY_HOP, IpNumber::IPV6_HEADER_HOP_BY_HOP),
            (ICMP, IpNumber::ICMP),
            (IGMP, IpNumber::IGMP),
            (GGP, IpNumber::GGP),
            (IPV4, IpNumber::IPV4),
            (STREAM, IpNumber::STREAM),
            (TCP, IpNumber::TCP),
            (CBT, IpNumber::CBT),
            (EGP, IpNumber::EGP),
            (IGP, IpNumber::IGP),
            (BBN_RCC_MON, IpNumber::BBN_RCC_MON),
            (NVP_II, IpNumber::NVP_II),
            (PUP, IpNumber::PUP),
            (ARGUS, IpNumber::ARGUS),
            (EMCON, IpNumber::EMCON),
            (XNET, IpNumber::XNET),
            (CHAOS, IpNumber::CHAOS),
            (UDP, IpNumber::UDP),
            (MUX, IpNumber::MUX),
            (DCN_MEAS, IpNumber::DCN_MEAS),
            (HMP, IpNumber::HMP),
            (PRM, IpNumber::PRM),
            (XNS_IDP, IpNumber::XNS_IDP),
            (TRUNK1, IpNumber::TRUNK1),
            (TRUNK2, IpNumber::TRUNK2),
            (LEAF1, IpNumber::LEAF1),
            (LEAF2, IpNumber::LEAF2),
            (RDP, IpNumber::RDP),
            (IRTP, IpNumber::IRTP),
            (ISO_TP4, IpNumber::ISO_TP4),
            (NET_BLT, IpNumber::NET_BLT),
            (MFE_NSP, IpNumber::MFE_NSP),
            (MERIT_INP, IpNumber::MERIT_INP),
            (DCCP, IpNumber::DCCP),
            (THIRD_PARTY_CONNECT_PROTOCOL, IpNumber::THIRD_PARTY_CONNECT_PROTOCOL),
            (IDPR, IpNumber::IDPR),
            (XTP, IpNumber::XTP),
            (DDP, IpNumber::DDP),
            (IDPR_CMTP, IpNumber::IDPR_CMTP),
            (TP_PLUS_PLUS, IpNumber::TP_PLUS_PLUS),
            (IL, IpNumber::IL),
            (IPV6, IpNumber::IPV6),
            (SDRP, IpNumber::SDRP),
            (IPV6_ROUTE_HEADER, IpNumber::IPV6_ROUTE_HEADER),
            (IPV6_ROUTE, IpNumber::IPV6_ROUTE_HEADER),
            (IPV6_FRAGMENTATION_HEADER, IpNumber::IPV6_FRAGMENTATION_HEADER),
            (IPV6_FRAG, IpNumber::IPV6_FRAGMENTATION_HEADER),
            (IDRP, IpNumber::IDRP),
            (RSVP, IpNumber::RSVP),
            (GRE, IpNumber::GRE),
            (DSR, IpNumber::DSR),
            (BNA, IpNumber::BNA),
            (ENCAP_SEC, IpNumber::ENCAPSULATING_SECURITY_PAYLOAD),
            (ENCAPSULATING_SECURITY_PAYLOAD, IpNumber::ENCAPSULATING_SECURITY_PAYLOAD),
            (AUTH, IpNumber::AUTHENTICATION_HEADER),
            (AUTHENTICATION_HEADER, IpNumber::AUTHENTICATION_HEADER),
            (INLSP, IpNumber::INLSP),
            (SWIPE, IpNumber::SWIPE),
            (NARP, IpNumber::NARP),
            (MOBILE, IpNumber::MOBILE),
            (TLSP, IpNumber::TLSP),
            (SKIP, IpNumber::SKIP),
            (IPV6_ICMP, IpNumber::IPV6_ICMP),
            (IPV6_NO_NEXT_HEADER, IpNumber::IPV6_NO_NEXT_HEADER),
            (IPV6_DEST_OPTIONS, IpNumber::IPV6_DESTINATION_OPTIONS),
            (IPV6_DESTINATION_OPTIONS, IpNumber::IPV6_DESTINATION_OPTIONS),
            (ANY_HOST_INTERNAL_PROTOCOL, IpNumber::ANY_HOST_INTERNAL_PROTOCOL),
            (CFTP, IpNumber::CFTP),
            (ANY_LOCAL_NETWORK, IpNumber::ANY_LOCAL_NETWORK),
            (SAT_EXPAK, IpNumber::SAT_EXPAK),
            (KRYTOLAN, IpNumber::KRYTOLAN),
            (RVD, IpNumber::RVD),
            (IPPC, IpNumber::IPPC),
            (ANY_DISTRIBUTED_FILE_SYSTEM, IpNumber::ANY_DISTRIBUTED_FILE_SYSTEM),
            (SAT_MON, IpNumber::SAT_MON),
            (VISA, IpNumber::VISA),
            (IPCV, IpNumber::IPCV),
            (CPNX, IpNumber::CPNX),
            (CPHB, IpNumber::CPHB),
            (WSN, IpNumber::WSN),
            (PVP, IpNumber::PVP),
            (BR_SAT_MON, IpNumber::BR_SAT_MON),
            (SUN_ND, IpNumber::SUN_ND),
            (WB_MON, IpNumber::WB_MON),
            (WB_EXPAK, IpNumber::WB_EXPAK),
            (ISO_IP, IpNumber::ISO_IP),
            (VMTP, IpNumber::VMTP),
            (SECURE_VMTP, IpNumber::SECURE_VMTP),
            (VINES, IpNumber::VINES),
            (TTP_OR_IPTM, IpNumber::TTP_OR_IPTM),
            (NSFNET_IGP, IpNumber::NSFNET_IGP),
            (DGP, IpNumber::DGP),
            (TCF, IpNumber::TCF),
            (EIGRP, IpNumber::EIGRP),
            (OSPFIGP, IpNumber::OSPFIGP),
            (SPRITE_RPC, IpNumber::SPRITE_RPC),
            (LARP, IpNumber::LARP),
            (MTP, IpNumber::MTP),
            (AX25, IpNumber::AX25),
            (IPIP, IpNumber::IPIP),
            (MICP, IpNumber::MICP),
            (SCC_SP, IpNumber::SCC_SP),
            (ETHER_IP, IpNumber::ETHER_IP),
            (ENCAP, IpNumber::ENCAP),
            (GMTP, IpNumber::GMTP),
            (IFMP, IpNumber::IFMP),
            (PNNI, IpNumber::PNNI),
            (PIM, IpNumber::PIM),
            (ARIS, IpNumber::ARIS),
            (SCPS, IpNumber::SCPS),
            (QNX, IpNumber::QNX),
            (ACTIVE_NETWORKS, IpNumber::ACTIVE_NETWORKS),
            (IP_COMP, IpNumber::IP_COMP),
            (SITRA_NETWORKS_PROTOCOL, IpNumber::SITRA_NETWORKS_PROTOCOL),
            (COMPAQ_PEER, IpNumber::COMPAQ_PEER),
            (IPX_IN_IP, IpNumber::IPX_IN_IP),
            (VRRP, IpNumber::VRRP),
            (PGM, IpNumber::PGM),
            (ANY_ZERO_HOP_PROTOCOL, IpNumber::ANY_ZERO_HOP_PROTOCOL),
            (LAYER2_TUNNELING_PROTOCOL, IpNumber::LAYER2_TUNNELING_PROTOCOL),
            (DDX, IpNumber::DDX),
            (IATP, IpNumber::IATP),
            (STP, IpNumber::STP),
            (SRP, IpNumber::SRP),
            (UTI, IpNumber::UTI),
            (SIMPLE_MESSAGE_PROTOCOL, IpNumber::SIMPLE_MESSAGE_PROTOCOL),
            (SM, IpNumber::SM),
            (PTP, IpNumber::PTP),
            (ISIS_OVER_IPV4, IpNumber::ISIS_OVER_IPV4),
            (FIRE, IpNumber::FIRE),
            (CRTP, IpNumber::CRTP),
            (CRUDP, IpNumber::CRUDP),
            (SSCOPMCE, IpNumber::SSCOPMCE),
            (IPLT, IpNumber::IPLT),
            (SPS, IpNumber::SPS),
            (PIPE, IpNumber::PIPE),
            (SCTP, IpNumber::SCTP),
            (FC, IpNumber::FC),
            (RSVP_E2E_IGNORE, IpNumber::RSVP_E2E_IGNORE),
            (MOBILITY, IpNumber::MOBILITY_HEADER),
            (MOBILITY_HEADER, IpNumber::MOBILITY_HEADER),
            (UDP_LITE, IpNumber::UDP_LITE),
            (MPLS_IN_IP, IpNumber::MPLS_IN_IP),
            (MANET, IpNumber::MANET),
            (HIP, IpNumber::HIP),
            (SHIM6, IpNumber::SHIM6),
            (WESP, IpNumber::WESP),
            (ROHC, IpNumber::ROHC),
            (EXP0, IpNumber::EXPERIMENTAL_AND_TESTING_0),
            (EXPERIMENTAL_AND_TESTING_0, IpNumber::EXPERIMENTAL_AND_TESTING_0),
            (EXP1, IpNumber::EXPERIMENTAL_AND_TESTING_1),
            (EXPERIMENTAL_AND_TESTING_1, IpNumber::EXPERIMENTAL_AND_TESTING_1),
        ];
        for (raw, enum_value) in pairs {
            assert_eq!(*raw, *enum_value);
        }
    }

    #[test]
    fn default() {
        let actual: IpNumber = Default::default();
        assert_eq!(actual, IpNumber(255));
    }

    #[test]
    fn debug() {
        let pairs = &[
            (IpNumber::IPV6_HEADER_HOP_BY_HOP, "Ipv6HeaderHopByHop(0)"),
            (IpNumber::ICMP, "ICMP(1)"),
            (IpNumber::IGMP, "IGMP(2)"),
            (IpNumber::GGP, "GGP(3)"),
            (IpNumber::IPV4, "Ipv4(4)"),
            (IpNumber::STREAM, "Stream(5)"),
            (IpNumber::TCP, "TCP(6)"),
            (IpNumber::UDP, "UDP(17)"),
            (IpNumber::IPV6, "Ipv6(41)"),
            (IpNumber::IPV6_ROUTE_HEADER, "Ipv6RouteHeader(43)"),
            (
                IpNumber::IPV6_FRAGMENTATION_HEADER,
                "Ipv6FragmentationHeader(44)",
            ),
            (
                IpNumber::ENCAPSULATING_SECURITY_PAYLOAD,
                "EncapsulatingSecurityPayload(50)",
            ),
            (IpNumber::AUTHENTICATION_HEADER, "AuthenticationHeader(51)"),
            (IpNumber::IPV6_ICMP, "ICMPv6(58)"),
            (
                IpNumber::IPV6_DESTINATION_OPTIONS,
                "Ipv6DestinationOptions(60)",
            ),
            (IpNumber::MOBILITY_HEADER, "MobilityHeader(135)"),
            (IpNumber::HIP, "HIP(139)"),
            (IpNumber::SHIM6, "SHIM6(140)"),
            (IpNumber::EXPERIMENTAL_AND_TESTING_0, "IpNumber(253)"),
            (IpNumber::EXPERIMENTAL_AND_TESTING_1, "IpNumber(254)"),
        ];

        for (ip_number, debug_str) in pairs {
            assert_eq!(format!("{:?}", ip_number), *debug_str);
        }
    }

    #[test]
    fn clone_eq_hash_ord() {
        // clone eq
        let value = IpNumber::IPV6_HEADER_HOP_BY_HOP;
        assert_eq!(value, value.clone());
        // hash
        let a_hash = {
            let mut s = DefaultHasher::new();
            value.hash(&mut s);
            s.finish()
        };
        let b_hash = {
            let mut s = DefaultHasher::new();
            value.hash(&mut s);
            s.finish()
        };
        assert_eq!(a_hash, b_hash);
        // order
        assert_eq!(value.cmp(&value.clone()), Ordering::Equal);
        assert!(value.ge(&value.clone()));
    }
}
