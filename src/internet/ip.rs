use super::super::*;

extern crate byteorder;
use self::byteorder::ReadBytesExt;

///Internet protocol headers version 4 & 6
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpHeader {
    Version4(Ipv4Header, Ipv4Extensions),
    Version6(Ipv6Header, Ipv6Extensions)
}

impl IpHeader {
    ///Read an IpvHeader from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(IpHeader, u8, &[u8]), ReadError> {
        use crate::ReadError::*;
        if slice.is_empty() {
            Err(UnexpectedEndOfSlice(1))
        } else {
            match slice[0] >> 4 {
                4 => {
                    let (header, rest) = Ipv4Header::read_from_slice(slice)?;
                    Ipv4Extensions::read_from_slice(header.protocol, rest).map(
                        |(ext, next_protocol, rest)|
                        (IpHeader::Version4(header, ext), next_protocol, rest)
                    )
                },
                6 => {
                    let (header, rest) = Ipv6Header::read_from_slice(slice)?;
                    Ipv6Extensions::read_from_slice(header.next_header, rest).map(
                        |(ext, next_protocol, rest)| 
                        (IpHeader::Version6(header, ext), next_protocol, rest)
                    )
                },
                version => Err(ReadError::IpUnsupportedVersion(version))
            }
        }
    }

    ///Reads an IP (v4 or v6) header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<(IpHeader, u8), ReadError> {
        let value = reader.read_u8()?;
        match value >> 4 {
            4 => {
                let header = Ipv4Header::read_without_version(reader, value & 0xf)?;
                Ipv4Extensions::read(reader, header.protocol).map( 
                    |(ext, next)| (IpHeader::Version4(header, ext), next)
                )
            },
            6 => {
                let header = Ipv6Header::read_without_version(reader, value & 0xf)?;
                Ipv6Extensions::read(reader, header.next_header).map(
                    |(ext, next)| (IpHeader::Version6(header, ext), next)
                )
            },
            version => Err(ReadError::IpUnsupportedVersion(version))
        }
    }

    ///Writes an IP (v4 or v6) header to the current position
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::IpHeader::*;
        match *self {
            Version4(ref header, ref extensions) => {
                header.write(writer)?;
                extensions.write(writer, header.protocol)
            }
            Version6(ref header, ref extensions) => {
                header.write(writer)?;
                extensions.write(writer, header.next_header)
            }
        }
    }
}

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
#[deprecated(
    since = "0.10.0",
    note = "Please use the type IpNumber instead"
)]
pub type IpTrafficClass = IpNumber;

/// Identifiers for the next_header field in ipv6 headers and protocol field in ipv4 headers.
///
/// `u8` contants of the ip numbers can be found in the module [ip_number].
///
/// The list was extracted from <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IpNumber {
    ///IPv6 Hop-by-Hop Option \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    IPv6HeaderHopByHop = 0,
    ///Internet Control Message \[[RFC792](https://datatracker.ietf.org/doc/html/rfc792)\]
    Icmp = 1,
    ///Internet Group Management \[[RFC1112](https://datatracker.ietf.org/doc/html/rfc1112)\]
    Igmp = 2,
    ///Gateway-to-Gateway \[[RFC823](https://datatracker.ietf.org/doc/html/rfc823)\]
    Ggp = 3,
    ///IPv4 encapsulation \[[RFC2003](https://datatracker.ietf.org/doc/html/rfc2003)\]
    IPv4 = 4,
    ///Stream \[[RFC1190](https://datatracker.ietf.org/doc/html/rfc1190)\] \[[RFC1819](https://datatracker.ietf.org/doc/html/rfc1819)\]
    Stream = 5,
    ///Transmission Control \[[RFC793](https://datatracker.ietf.org/doc/html/rfc793)\]
    Tcp = 6,
    ///CBT \[Tony_Ballardie\]
    Cbt = 7,
    ///Exterior Gateway Protocol \[[RFC888](https://datatracker.ietf.org/doc/html/rfc888)\] \[David_Mills\]
    Egp = 8,
    ///any private interior gateway (used by Cisco for their IGRP) \[Internet_Assigned_Numbers_Authority\]
    Igp = 9,
    ///BBN RCC Monitoring \[Steve_Chipman\]
    BbnRccMon = 10,
    ///Network Voice Protocol \[[RFC741](https://datatracker.ietf.org/doc/html/rfc741)\]\[Steve_Casner\]
    NvpII = 11,
    ///PUP
    Pup = 12,
    ///ARGUS (deprecated) \[Robert_W_Scheifler\]
    Argus = 13,
    ///EMCON \[mystery contact\]
    Emcon = 14,
    ///Cross Net Debugger \[Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.\]\[Jack_Haverty\]
    Xnet = 15,
    ///Chaos \[J_Noel_Chiappa\]
    Chaos = 16,
    ///User Datagram \[[RFC768](https://datatracker.ietf.org/doc/html/rfc768)\]\[Jon_Postel\]
    Udp = 17,
    ///Multiplexing \[Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.\]\[Jon_Postel\]
    Mux = 18,
    ///DCN Measurement Subsystems \[David_Mills\]
    DcnMeas = 19,
    ///Host Monitoring \[[RFC869](https://datatracker.ietf.org/doc/html/rfc869)\]\[Bob_Hinden\]
    Hmp = 20,
    ///Packet Radio Measurement \[Zaw_Sing_Su\]
    Prm = 21,
    ///XEROX NS IDP
    XnsIdp = 22,
    ///Trunk-1 \[Barry_Boehm\]
    Trunk1 = 23,
    ///Trunk-2 \[Barry_Boehm\]
    Trunk2 = 24,
    ///Leaf-1 \[Barry_Boehm\]
    Leaf1 = 25,
    ///Leaf-2 \[Barry_Boehm\]
    Leaf2 = 26,
    ///Reliable Data Protocol \[[RFC908](https://datatracker.ietf.org/doc/html/rfc908)\] \[Bob_Hinden\]
    Rdp = 27,
    ///Internet Reliable Transaction \[[RFC938](https://datatracker.ietf.org/doc/html/rfc938)\] \[Trudy_Miller\]
    Irtp = 28,
    ///ISO Transport Protocol Class 4 \[[RFC905](https://datatracker.ietf.org/doc/html/rfc905)\] \[<mystery contact>\]
    IsoTp4 = 29,
    ///Bulk Data Transfer Protocol \[[RFC969](https://datatracker.ietf.org/doc/html/rfc969)\] \[David_Clark\]
    NetBlt = 30,
    ///MFE Network Services Protocol \[Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.\] \[Barry_Howard\]
    MfeNsp = 31,
    ///MERIT Internodal Protocol \[Hans_Werner_Braun\]
    MeritInp = 32,
    ///Datagram Congestion Control Protocol \[[RFC4340](https://datatracker.ietf.org/doc/html/rfc4340)\]
    Dccp = 33,
    ///Third Party Connect Protocol \[Stuart_A_Friedberg\]
    ThirdPartyConnectProtocol = 34,
    ///Inter-Domain Policy Routing Protocol \[Martha_Steenstrup\]
    Idpr = 35,
    ///XTP \[Greg_Chesson\]
    Xtp = 36,
    ///Datagram Delivery Protocol \[Wesley_Craig\]
    Ddp = 37,
    ///IDPR Control Message Transport Proto \[Martha_Steenstrup\]
    IdprCmtp = 38,
    ///TP++ Transport Protocol \[Dirk_Fromhein\]
    TpPlusPlus = 39,
    ///IL Transport Protocol \[Dave_Presotto\]
    Il = 40,
    ///IPv6 encapsulation \[[RFC2473](https://datatracker.ietf.org/doc/html/rfc2473)\]
    Ipv6 = 41,
    ///Source Demand Routing Protocol \[Deborah_Estrin\]
    Sdrp = 42,
    ///Routing Header for IPv6 \[Steve_Deering\]
    IPv6RouteHeader = 43,
    ///Fragment Header for IPv6 \[Steve_Deering\]
    IPv6FragmentationHeader = 44,
    ///Inter-Domain Routing Protocol \[Sue_Hares\]
    Idrp = 45,
    ///Reservation Protocol \[[RFC2205](https://datatracker.ietf.org/doc/html/rfc2205)\]\[[RFC3209](https://datatracker.ietf.org/doc/html/rfc3209)\]\[Bob_Braden\]
    Rsvp = 46,
    ///Generic Routing Encapsulation \[[RFC2784](https://datatracker.ietf.org/doc/html/rfc2784)\]\[Tony_Li\]
    Gre = 47,
    ///Dynamic Source Routing Protocol \[[RFC4728](https://datatracker.ietf.org/doc/html/rfc4728)\]
    Dsr = 48,
    ///BNA \[Gary Salamon\]
    Bna = 49,
    ///Encapsulating Security Payload \[[RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)\]
    EncapsulatingSecurityPayload = 50,
    ///Authentication Header \[[RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)\]
    AuthenticationHeader = 51,
    ///Integrated Net Layer Security  TUBA \[K_Robert_Glenn\]
    Inlsp = 52,
    ///IP with Encryption (deprecated) \[John_Ioannidis\]
    Swipe = 53,
    ///NBMA Address Resolution Protocol \[[RFC1735](https://datatracker.ietf.org/doc/html/rfc1735)\]
    Narp = 54,
    ///IP Mobility \[Charlie_Perkins\]
    Mobile = 55,
    ///Transport Layer Security Protocol using Kryptonet key management \[Christer_Oberg\]
    Tlsp = 56,
    ///SKIP \[Tom_Markson\]
    Skip = 57,
    ///ICMP for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    IPv6Icmp = 58,
    ///No Next Header for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    IPv6NoNextHeader = 59,
    ///Destination Options for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    IPv6DestinationOptions = 60,
    ///any host internal protocol \[Internet_Assigned_Numbers_Authority\]
    AnyHostInternalProtocol = 61,
    ///CFTP \[Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.\]\[Harry_Forsdick\]
    Cftp = 62,
    ///any local network \[Internet_Assigned_Numbers_Authority\]
    AnyLocalNetwork = 63,
    ///SATNET and Backroom EXPAK \[Steven_Blumenthal\]
    SatExpak = 64,
    ///Kryptolan \[Paul Liu\]
    Krytolan = 65,
    ///MIT Remote Virtual Disk Protocol \[Michael_Greenwald\]
    Rvd = 66,
    ///Internet Pluribus Packet Core \[Steven_Blumenthal\]
    Ippc = 67,
    ///any distributed file system \[Internet_Assigned_Numbers_Authority\]
    AnyDistributedFileSystem = 68,
    ///SATNET Monitoring \[Steven_Blumenthal\]
    SatMon = 69,
    ///VISA Protocol \[Gene_Tsudik\]
    Visa = 70,
    ///Internet Packet Core Utility \[Steven_Blumenthal\]
    Ipcv = 71,
    ///Computer Protocol Network Executive \[David Mittnacht\]
    Cpnx = 72,
    ///Computer Protocol Heart Beat \[David Mittnacht\]
    Cphb = 73,
    ///Wang Span Network \[Victor Dafoulas\]
    Wsn = 74,
    ///Packet Video Protocol \[Steve_Casner\]
    Pvp = 75,
    ///Backroom SATNET Monitoring \[Steven_Blumenthal\]
    BrSatMon = 76,
    ///SUN ND PROTOCOL-Temporary \[William_Melohn\]
    SunNd = 77,
    ///WIDEBAND Monitoring \[Steven_Blumenthal\]
    WbMon = 78,
    ///WIDEBAND EXPAK \[Steven_Blumenthal\]
    WbExpak = 79,
    ///ISO Internet Protocol \[Marshall_T_Rose\]
    IsoIp = 80,
    ///VMTP \[Dave_Cheriton\]
    Vmtp = 81,
    ///SECURE-VMTP \[Dave_Cheriton\]
    SecureVmtp = 82,
    ///VINES \[Brian Horn\]
    Vines = 83,
    ///Transaction Transport Protocol or Internet Protocol Traffic Manager \[Jim_Stevens\]
    TtpOrIptm = 84,
    ///NSFNET-IGP \[Hans_Werner_Braun\]
    NsfnetIgp = 85,
    ///Dissimilar Gateway Protocol \[M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.\]\[Mike_Little\]
    Dgp = 86,
    ///TCF \[Guillermo_A_Loyola\]
    Tcf = 87,
    ///EIGRP \[[RFC7868](https://datatracker.ietf.org/doc/html/rfc7868)\]
    Eigrp = 88,
    ///OSPFIGP \[[RFC1583](https://datatracker.ietf.org/doc/html/rfc1583)\]\[[RFC2328](https://datatracker.ietf.org/doc/html/rfc2328)\]\[[RFC5340](https://datatracker.ietf.org/doc/html/rfc5340)\]\[John_Moy\]
    Ospfigp = 89,
    ///Sprite RPC Protocol \[Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.\]\[Bruce Willins\]
    SpriteRpc = 90,
    ///Locus Address Resolution Protocol \[Brian Horn\]
    Larp = 91,
    ///Multicast Transport Protocol \[Susie_Armstrong\]
    Mtp = 92,
    ///AX.25 Frames \[Brian_Kantor\]
    Ax25 = 93,
    ///IP-within-IP Encapsulation Protocol \[John_Ioannidis\]
    Ipip = 94,
    ///Mobile Internetworking Control Pro. (deprecated) \[John_Ioannidis\]
    Micp = 95,
    ///Semaphore Communications Sec. Pro. \[Howard_Hart\]
    SccSp = 96,
    ///Ethernet-within-IP Encapsulation \[[RFC3378](https://datatracker.ietf.org/doc/html/rfc3378)\]
    EtherIp = 97,
    ///Encapsulation Header \[[RFC1241](https://datatracker.ietf.org/doc/html/rfc1241)\]\[Robert_Woodburn\]
    Encap = 98,
    ///GMTP \[\[RXB5\]\]
    Gmtp = 100,
    ///Ipsilon Flow Management Protocol \[Bob_Hinden\]\[November 1995, 1997.\]
    Ifmp = 101,
    ///PNNI over IP \[Ross_Callon\]
    Pnni = 102,
    ///Protocol Independent Multicast \[[RFC7761](https://datatracker.ietf.org/doc/html/rfc7761)\]\[Dino_Farinacci\]
    Pim = 103,
    ///ARIS \[Nancy_Feldman\]
    Aris = 104,
    ///SCPS \[Robert_Durst\]
    Scps = 105,
    ///QNX \[Michael_Hunter\]
    Qnx = 106,
    ///Active Networks \[Bob_Braden\]
    ActiveNetworks = 107,
    ///IP Payload Compression Protocol \[[RFC2393](https://datatracker.ietf.org/doc/html/rfc2393)\]
    IpComp = 108,
    ///Sitara Networks Protocol \[Manickam_R_Sridhar\]
    SitraNetworksProtocol = 109,
    ///Compaq Peer Protocol \[Victor_Volpe\]
    CompaqPeer = 110,
    ///IPX in IP \[CJ_Lee\]
    IpxInIp = 111,
    ///Virtual Router Redundancy Protocol \[[RFC5798](https://datatracker.ietf.org/doc/html/rfc5798)\]
    Vrrp = 112,
    ///PGM Reliable Transport Protocol \[Tony_Speakman\]
    Pgm = 113,
    ///any 0-hop protocol \[Internet_Assigned_Numbers_Authority\]
    AnyZeroHopProtocol = 114,
    ///Layer Two Tunneling Protocol \[[RFC3931](https://datatracker.ietf.org/doc/html/rfc3931)\]\[Bernard_Aboba\]
    Layer2TunnelingProtocol = 115,
    ///D-II Data Exchange (DDX) \[John_Worley\]
    Ddx = 116,
    ///Interactive Agent Transfer Protocol \[John_Murphy\]
    Iatp = 117,
    ///Schedule Transfer Protocol \[Jean_Michel_Pittet\]
    Stp = 118,
    ///SpectraLink Radio Protocol \[Mark_Hamilton\]
    Srp = 119,
    ///UTI \[Peter_Lothberg\]
    Uti = 120,
    ///Simple Message Protocol \[Leif_Ekblad\]
    SimpleMessageProtocol = 121,
    ///Simple Multicast Protocol (deprecated) \[Jon_Crowcroft\]\[draft-perlman-simple-multicast\]
    Sm = 122,
    ///Performance Transparency Protocol \[Michael_Welzl\]
    Ptp = 123,
    ///ISIS over IPv4 \[Tony_Przygienda\]
    IsisOverIpv4 = 124,
    ///FIRE \[Criag_Partridge\]
    Fire = 125,
    ///Combat Radio Transport Protocol \[Robert_Sautter\]
    Crtp = 126,
    ///Combat Radio User Datagram \[Robert_Sautter\]
    Crudp = 127,
    ///SSCOPMCE \[Kurt_Waber\]
    Sscopmce = 128,
    ///IPLT \[\[Hollbach\]\]
    Iplt = 129,
    ///Secure Packet Shield \[Bill_McIntosh\]
    Sps = 130,
    ///Private IP Encapsulation within IP \[Bernhard_Petri\]
    Pipe = 131,
    ///Stream Control Transmission Protocol \[Randall_R_Stewart\]
    Sctp = 132,
    ///Fibre Channel \[Murali_Rajagopal\]\[[RFC6172](https://datatracker.ietf.org/doc/html/rfc6172)\]
    Fc = 133,
    ///RSVP-E2E-IGNORE \[[RFC3175](https://datatracker.ietf.org/doc/html/rfc3175)\]
    RsvpE2eIgnore = 134,
    ///MobilityHeader \[[RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)\]
    MobilityHeader = 135,
    ///UDPLite \[[RFC3828](https://datatracker.ietf.org/doc/html/rfc3828)\]
    UdpLite = 136,
    /// \[[RFC4023](https://datatracker.ietf.org/doc/html/rfc4023)\]
    MplsInIp = 137,
    ///MANET Protocols \[[RFC5498](https://datatracker.ietf.org/doc/html/rfc5498)\]
    Manet = 138,
    ///Host Identity Protocol \[[RFC7401](https://datatracker.ietf.org/doc/html/rfc7401)\]
    Hip = 139,
    ///Shim6 Protocol \[[RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)\]
    Shim6 = 140,
    ///Wrapped Encapsulating Security Payload \[[RFC5840](https://datatracker.ietf.org/doc/html/rfc5840)\]
    Wesp = 141,
    ///Robust Header Compression \[[RFC5858](https://datatracker.ietf.org/doc/html/rfc5858)\]
    Rohc = 142,
    ///Use for experimentation and testing
    ExperimentalAndTesting0 = 253,
    ///Use for experimentation and testing
    ExperimentalAndTesting1 = 254
}

impl IpNumber {

    /// Returns true if the given number is the internet number of an IPV6 extension header.
    pub fn is_ipv6_ext_header_value(value: u8) -> bool {
        use crate::ip_number::*;

        match value {
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_FRAG | ENCAP_SEC | AUTH 
            | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 | EXP0 | EXP1
                => true,
            _ => false
        }
    }
}

/// Module containing the u8 constants for the most used ip protocol number.
///
/// The constants only exist for convenience. You can get equivalent values by 
/// casting the enum values of [IpNumber] to a u8 value.
///
/// ```
/// use etherparse::{ip_number, IpNumber};
///
/// assert_eq!(ip_number::TCP, IpNumber::Tcp as u8);
/// ```
///
/// The list original values were copied from
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
pub mod ip_number {
    use crate::IpNumber::*;

    ///IPv6 Hop-by-Hop Option \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_HOP_BY_HOP: u8 = IPv6HeaderHopByHop as u8; //0
    ///Internet Control Message \[[RFC792](https://datatracker.ietf.org/doc/html/rfc792)\]
    pub const ICMP: u8 = Icmp as u8; //1
    ///Internet Group Management \[[RFC1112](https://datatracker.ietf.org/doc/html/rfc1112)\]
    pub const IGMP: u8 = Igmp as u8; //2
    ///Gateway-to-Gateway \[[RFC823](https://datatracker.ietf.org/doc/html/rfc823)\]
    pub const GGP: u8 = Ggp as u8; //3
    ///IPv4 encapsulation \[[RFC2003](https://datatracker.ietf.org/doc/html/rfc2003)\]
    pub const IPV4: u8 = IPv4 as u8; //4
    ///Stream \[[RFC1190](https://datatracker.ietf.org/doc/html/rfc1190)\] \[[RFC1819](https://datatracker.ietf.org/doc/html/rfc1819)\]
    pub const STREAM: u8 = Stream as u8; //5
    ///Transmission Control \[[RFC793](https://datatracker.ietf.org/doc/html/rfc793)\]
    pub const TCP: u8 = Tcp as u8; //6
    ///User Datagram \[[RFC768](https://datatracker.ietf.org/doc/html/rfc768)\] \[Jon_Postel\]
    pub const UDP: u8 = Udp as u8; //17
    ///IPv6 encapsulation \[[RFC2473](https://datatracker.ietf.org/doc/html/rfc2473)\]
    pub const IPV6: u8 = Ipv6 as u8; //41
    ///Routing Header for IPv6 \[Steve_Deering\]
    pub const IPV6_ROUTE: u8 = IPv6RouteHeader as u8; //43
    ///Fragment Header for IPv6 \[Steve_Deering\]
    pub const IPV6_FRAG: u8 = IPv6FragmentationHeader as u8; //44
    ///Encapsulating Security Payload \[[RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)\]
    pub const ENCAP_SEC: u8 = EncapsulatingSecurityPayload as u8; //50
    ///Authentication Header \[[RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)\]
    pub const AUTH: u8 = AuthenticationHeader as u8; //51
    ///Destination Options for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    pub const IPV6_DEST_OPTIONS: u8 = IPv6DestinationOptions as u8; //60
    ///MobilityHeader \[[RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)\]
    pub const MOBILITY: u8 = MobilityHeader as u8; //135
    ///Host Identity Protocol \[[RFC7401](https://datatracker.ietf.org/doc/html/rfc7401)\]
    pub const HIP: u8 = Hip as u8; //139
    ///Shim6 Protocol \[[RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)\]
    pub const SHIM6: u8 = Shim6 as u8; //140
    ///Use for experimentation and testing
    pub const EXP0: u8 = ExperimentalAndTesting0 as u8; //253
    ///Use for experimentation and testing
    pub const EXP1: u8 = ExperimentalAndTesting1 as u8; //254
}
