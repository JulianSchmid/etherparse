extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;

///Ether type enum present in ethernet II header.
#[derive(Debug, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    VlanDoubleTaggedFrame = 0x9100
}

impl EtherType {
    ///Tries to convert a raw ether type value to the enum. Returns None if the value does not exist in the enum.
    pub fn from_u16(value: u16) -> Option<EtherType> {
        use EtherType::*;
        match value {
            0x0800 => Some(Ipv4),
            0x86dd => Some(Ipv6),
            0x0806 => Some(Arp),
            0x0842 => Some(WakeOnLan),
            0x8100 => Some(VlanTaggedFrame),
            0x9100 => Some(VlanDoubleTaggedFrame),
            _ => None
        }
    }
}

///Ethernet II header.
#[derive(Debug, PartialEq)]
pub struct Ethernet2Header {
    pub destination: [u8;6],
    pub source: [u8;6],
    pub ether_type: u16
}
///IEEE 802.1Q VLAN Tagging Header
#[derive(Debug, PartialEq)]
pub struct VlanTaggingHeader {
    ///A 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub priority_code_point: u8,
    ///Indicate that the frame may be dropped under the presence of congestion.
    pub drop_eligible_indicator: bool,
    ///12 bits vland identifier.
    pub vlan_identifier: u16,
    ///"Tag protocol identifier": Type id of content after this header. Refer to the "EtherType" for a list of possible supported values.
    pub ether_type: u16,
}

///Internet protocol headers
#[derive(Debug, PartialEq)]
pub enum IpHeader {
    Version4(Ipv4Header),
    Version6(Ipv6Header)
}

///IPv4 header without options.
#[derive(Debug, PartialEq)]
pub struct Ipv4Header {
    pub header_length: u8,
    pub differentiated_services_code_point: u8,
    pub explicit_congestion_notification: u8,
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragments_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: [u8;4],
    pub destination: [u8;4]
}

///IPv6 header according to rfc8200.
#[derive(Debug, PartialEq)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    ///IPv6 source address
    pub source: [u8;16],
    ///IPv6 destination address
    pub destination: [u8;16]
}

///Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    IoError(io::Error),
    ///Error when the ip header version is not supported (only 4 & 6 are supported). The value is the version that was received.
    IpUnsupportedVersion(u8),
    ///Error when the ip header version field is not equal 4. The value is the version that was received.
    Ipv4UnexpectedVersion(u8),
    ///Error when then ip header version field is not equal 6. The value is the version that was received.
    Ipv6UnexpectedVersion(u8),
    ///Error when more then 7 header extensions are present (according to RFC82000 this should never happen).
    Ipv6TooManyHeaderExtensions
}

impl From<io::Error> for ReadError {
    fn from(err: io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

///Errors that can occur when writing.
#[derive(Debug)]
pub enum WriteError {
    IoError(io::Error),
    ///Error when a u8 field in a header has a larger value then supported.
    ValueU8TooLarge{value: u8, max: u8, field: ErrorField},
    ///Error when a u16 field in a header has a larger value then supported.
    ValueU16TooLarge{value: u16, max: u16, field: ErrorField},
    ///Error when a u32 field in a header has a larger value then supported.
    ValueU32TooLarge{value: u32, max: u32, field: ErrorField}
}

impl From<io::Error> for WriteError {
    fn from(err: io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

///Fields that can produce errors when serialized.
#[derive(Debug)]
pub enum ErrorField {
    Ipv4HeaderLength,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4FragmentsOffset,

    Ipv6FlowLabel,

    ///VlanTaggingHeader.priority_code_point
    VlanTagPriorityCodePoint,
    ///VlanTaggingHeader.vlan_identifier
    VlanTagVlanId
}

///Helper for writing headers.
///Import this for adding write functions to every struct that implements the trait Read.
pub trait WriteEtherExt: io::Write {

    ///Writes a given Ethernet-II header to the current position.
    fn write_ethernet2_header(&mut self, value: &Ethernet2Header) -> Result<(), io::Error> {
        self.write_all(&value.destination)?;
        self.write_all(&value.source)?;
        self.write_u16::<BigEndian>(value.ether_type)?;
        Ok(())
    }

    ///Write a IEEE 802.1Q VLAN tagging header
    fn write_vlan_tagging_header(&mut self, value: &VlanTaggingHeader) -> Result<(), WriteError> {
        use ErrorField::*;
        //check value ranges
        max_check_u8(value.priority_code_point, 0x3, VlanTagPriorityCodePoint)?;
        max_check_u16(value.vlan_identifier, 0xfff, VlanTagVlanId)?;
        {
            let mut buffer: [u8;2] = [0;2];
            BigEndian::write_u16(&mut buffer, value.vlan_identifier);
            if value.drop_eligible_indicator {
                buffer[0] = buffer[0] | 0x10;
            }
            buffer[0] = buffer[0] | (value.priority_code_point << 5);
            self.write_all(&buffer)?;
        }
        self.write_u16::<BigEndian>(value.ether_type)?;
        Ok(())
    }

    ///Writes a given IPv4 header to the current position.
    fn write_ipv4_header(&mut self, value: &Ipv4Header) -> Result<(), WriteError> {
        use ErrorField::*;
        
        //check ranges
        max_check_u8(value.header_length, 0xf, Ipv4HeaderLength)?;
        max_check_u8(value.differentiated_services_code_point, 0x3f, Ipv4Dscp)?;
        max_check_u8(value.explicit_congestion_notification, 0x3, Ipv4Ecn)?;
        max_check_u16(value.fragments_offset, 0x1fff, Ipv4FragmentsOffset)?;

        //version & header_length
        self.write_u8((4 << 4) | value.header_length)?;

        //dscp & ecn        
        self.write_u8((value.differentiated_services_code_point << 2) | value.explicit_congestion_notification)?;

        //total length & id 
        self.write_u16::<BigEndian>(value.total_length)?;
        self.write_u16::<BigEndian>(value.identification)?;

        //flags & fragmentation offset
        {
            let mut buf: [u8;2] = [0;2];
            BigEndian::write_u16(&mut buf, value.fragments_offset);
            let flags = {
                let mut result = 0;
                if value.dont_fragment {
                    result = result | 64;
                }
                if value.more_fragments {
                    result = result | 32;
                }
                result
            };
            self.write_u8(
                flags |
                (buf[0] & 0x1f),
            )?;
            self.write_u8(
                buf[1]
            )?;
        }

        //rest
        self.write_u8(value.time_to_live)?;
        self.write_u8(value.protocol)?;
        self.write_u16::<BigEndian>(value.header_checksum)?;
        self.write_all(&value.source)?;
        self.write_all(&value.destination)?;

        Ok(())
    }

    ///Writes a given IPv6 header to the current position.
    fn write_ipv6_header(&mut self, value: &Ipv6Header) -> Result<(), WriteError> {
        use WriteError::*;
        use ErrorField::*;
        fn max_check_u32(value: u32, max: u32, field: ErrorField) -> Result<(), WriteError> {
            if value <= max {
                Ok(())
            } else {
                Err(ValueU32TooLarge{ value: value, max: max, field: field })
            }
        };

        //version & traffic class p0
        self.write_u8((6 << 4) | (value.traffic_class >> 4))?;

        //flow label
        max_check_u32(value.flow_label, 0xfffff, Ipv6FlowLabel)?;
        {
            //write as a u32 to a buffer and write only the "lower bytes"
            let mut buffer: [u8; 4] = [0;4];
            byteorder::BigEndian::write_u32(&mut buffer, value.flow_label);
            //add the traffic_class
            buffer[1] = buffer[1] | (value.traffic_class << 4);
            //skip "highest" byte of big endian
            self.write_all(&buffer[1..])?;
        }

        //rest
        self.write_u16::<BigEndian>(value.payload_length)?;
        self.write_u8(value.next_header)?;
        self.write_u8(value.hop_limit)?;
        self.write_all(&value.source)?;
        self.write_all(&value.destination)?;

        Ok(())
    }
}

impl<W: io::Write + ?Sized> WriteEtherExt for W {}

///Helper for reading headers.
///Import this for adding read functions to every struct that implements the trait Read.
pub trait ReadEtherExt: io::Read + io::Seek {
    ///Reads an Ethernet-II header from the current position.
    fn read_ethernet2_header(&mut self) -> Result<Ethernet2Header, io::Error> {
        Ok(Ethernet2Header {
            destination: self.read_mac_address()?,
            source: self.read_mac_address()?,
            ether_type: self.read_u16::<BigEndian>()?
        })
    }

    ///Read a IEEE 802.1Q VLAN tagging header
    fn read_vlan_tagging_header(&mut self) -> Result<VlanTaggingHeader, WriteError> {
        let (priority_code_point, drop_eligible_indicator, vlan_identifier) = {
            let mut buffer: [u8;2] = [0;2];
            self.read_exact(&mut buffer)?;
            let drop_eligible_indicator = 0 != (buffer[0] & 0x10);
            let priority_code_point = buffer[0] >> 5;
            //mask and read the vlan id
            buffer[0] = buffer[0] & 0xf;
            (priority_code_point, drop_eligible_indicator, BigEndian::read_u16(&buffer))
        };

        Ok(VlanTaggingHeader{
            priority_code_point: priority_code_point,
            drop_eligible_indicator: drop_eligible_indicator,
            vlan_identifier: vlan_identifier,
            ether_type: self.read_u16::<BigEndian>()?
        })
    }

    ///Reads an IP (v4 or v6) header from the current position.
    fn read_ip_header(&mut self) -> Result<IpHeader, ReadError> {
        let value = self.read_u8()?;
        match value >> 4 {
            4 => Ok(IpHeader::Version4(self.read_ipv4_header_without_version(value & 0xf)?)),
            6 => Ok(IpHeader::Version6(self.read_ipv6_header_without_version(value & 0xf)?)),
            version => Err(ReadError::IpUnsupportedVersion(version))
        }
    }

    ///Reads an IPv4 header from the current position.
    fn read_ipv4_header(&mut self) -> Result<Ipv4Header, ReadError> {
        let value = self.read_u8()?;
        let version = value >> 4;
        if 4 != version {
            return Err(ReadError::Ipv4UnexpectedVersion(version));
        }
        self.read_ipv4_header_without_version(value & 0xf)
    }

    ///Reads an IPv4 header assuming the version & ihl field have already been read.
    fn read_ipv4_header_without_version(&mut self, version_rest: u8) -> Result<Ipv4Header, ReadError> {
        let ihl = version_rest;
        let (dscp, ecn) = {
            let value = self.read_u8()?;
            (value >> 2, value & 0x3)
        };
        let total_length = self.read_u16::<BigEndian>()?;
        let identification = self.read_u16::<BigEndian>()?;
        let (dont_fragment, more_fragments, fragments_offset) = {
            let mut values: [u8; 2] = [0;2];
            self.read_exact(&mut values)?;
            (0 != (values[0] & 0x40),
             0 != (values[0] & 0x20),
             {
                let buf = [values[0] & 0x1f, values[1]];
                let mut cursor = io::Cursor::new(&buf);
                cursor.read_u16::<BigEndian>()?
             })
        };
        Ok(Ipv4Header{
            differentiated_services_code_point: dscp,
            explicit_congestion_notification: ecn,
            total_length: total_length,
            identification: identification,
            dont_fragment: dont_fragment,
            more_fragments: more_fragments,
            fragments_offset: fragments_offset,
            time_to_live: self.read_u8()?,
            protocol: self.read_u8()?,
            header_checksum: self.read_u16::<BigEndian>()?,
            source: {
                let mut values: [u8;4] = [0;4];
                self.read_exact(&mut values)?;
                values
            },
            destination: {
                let mut values: [u8;4] = [0;4];
                self.read_exact(&mut values)?;
                values
            },
            header_length: ihl
        })
    }

    ///Reads an IPv6 header from the current position.
    fn read_ipv6_header(&mut self) -> Result<Ipv6Header, ReadError> {
        let value = self.read_u8()?;
        let version = value >> 4;
        if 6 != version {
            return Err(ReadError::Ipv6UnexpectedVersion(version));
        }
        self.read_ipv6_header_without_version(value & 0xf)
    }

    ///Reads an IPv6 header assuming the version & flow_label field have already been read.
    fn read_ipv6_header_without_version(&mut self, version_rest: u8) -> Result<Ipv6Header, ReadError> {
        let (traffic_class, flow_label) = {
            //read 4 bytes
            let mut buffer: [u8; 4] = [0;4];
            self.read_exact(&mut buffer[1..])?;

            //extract class
            let traffic_class = (version_rest << 4) | (buffer[1] >> 4);

            //remove traffic class from buffer & read flow_label
            buffer[1] = buffer[1] & 0xf;
            (traffic_class, byteorder::BigEndian::read_u32(&buffer))
        };
        
        Ok(Ipv6Header{
            traffic_class: traffic_class,
            flow_label: flow_label,
            payload_length: self.read_u16::<BigEndian>()?,
            next_header: self.read_u8()?,
            hop_limit: self.read_u8()?,
            source: {
                let mut buffer: [u8; 16] = [0;16];
                self.read_exact(&mut buffer)?;
                buffer
            },
            destination: {
                let mut buffer: [u8; 16] = [0;16];
                self.read_exact(&mut buffer)?;
                buffer
            }
        })
    }

    ///Skips the ipv6 header extension and returns the traffic_class
    fn skip_ipv6_header_extension(&mut self) -> Result<u8, ReadError> {
        let next_header = self.read_u8()?;
        //read the length
        //Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
        let rest_length = ((self.read_u8()? as i64)*8) + 8 - 2;
        self.seek(io::SeekFrom::Current(rest_length))?;
        Ok(next_header)
    }

    ///Skips all ipv6 header extensions and returns the last traffic_class
    fn skip_all_ipv6_header_extensions(&mut self, traffic_class: u8) -> Result<u8, ReadError> {
        use IpTrafficClass::*;
        const HOP_BY_HOP: u8 = IPv6HeaderHopByHop as u8;
        const ROUTE: u8 = IPv6RouteHeader as u8;
        const FRAG: u8 = IPv6FragmentationHeader as u8;
        const OPTIONS: u8 = IPv6DestinationOptions as u8;
        const AUTH: u8 = IPv6AuthenticationHeader as u8;
        const ENCAP_SEC: u8 = IPv6EncapSecurityPayload as u8;

        let mut next_traffic_class = traffic_class;
        for _i in 0..7 {
            match next_traffic_class {
                HOP_BY_HOP | ROUTE | FRAG | OPTIONS | AUTH | ENCAP_SEC => {
                    next_traffic_class = self.skip_ipv6_header_extension()?;
                },
                _ => return Ok(next_traffic_class)
            }
        }
        match next_traffic_class {
            HOP_BY_HOP | ROUTE | FRAG | OPTIONS | AUTH | ENCAP_SEC => Err(ReadError::Ipv6TooManyHeaderExtensions),
            value => Ok(value)
        }
    }

    fn read_mac_address(&mut self) -> Result<[u8;6], io::Error> {
        let mut result: [u8;6] = [0;6];
        self.read_exact(&mut result)?;
        Ok(result)
    }
}

impl<W: io::Read + io::Seek + ?Sized> ReadEtherExt for W {}

///Identifiers for the traffic_class field in ipv6 headers and protocol field in ipv4 headers.
pub enum IpTrafficClass {
    ///IPv6 Hop-by-Hop Option [RFC8200]
    IPv6HeaderHopByHop = 0,
    ///Internet Control Message [RFC792]
    Icmp = 1,
    ///Internet Group Management [RFC1112]
    Igmp = 2,
    ///Gateway-to-Gateway [RFC823]
    Ggp = 3,
    ///IPv4 encapsulation [RFC2003]
    IPv4 = 4,
    ///Stream [RFC1190][RFC1819]
    Stream = 5,
    ///Transmission Control [RFC793]
    Tcp = 6,
    ///CBT [Tony_Ballardie]
    Cbt = 7,
    ///Exterior Gateway Protocol [RFC888][David_Mills]
    Egp = 8,
    ///any private interior gateway (used by Cisco for their IGRP) [Internet_Assigned_Numbers_Authority]
    Igp = 9,
    ///BBN RCC Monitoring [Steve_Chipman]
    BbnRccMon = 10,
    ///Network Voice Protocol [RFC741][Steve_Casner]
    NvpII = 11,
    ///PUP
    Pup = 12,
    ///ARGUS (deprecated) [Robert_W_Scheifler]
    Argus = 13,
    ///EMCON [<mystery contact>]
    Emcon = 14,
    ///Cross Net Debugger [Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.][Jack_Haverty]
    Xnet = 15,
    ///Chaos [J_Noel_Chiappa]
    Chaos = 16,
    ///User Datagram [RFC768][Jon_Postel]
    Udp = 17,
    ///Multiplexing [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.][Jon_Postel]
    Mux = 18,
    ///DCN Measurement Subsystems [David_Mills]
    DcnMeas = 19,
    ///Host Monitoring [RFC869][Bob_Hinden]
    Hmp = 20,
    ///Packet Radio Measurement [Zaw_Sing_Su]
    Prm = 21,
    ///XEROX NS IDP
    XnsIdp = 22,
    ///Trunk-1 [Barry_Boehm]
    Trunk1 = 23,
    ///Trunk-2 [Barry_Boehm]
    Trunk2 = 24,
    ///Leaf-1 [Barry_Boehm]
    Leaf1 = 25,
    ///Leaf-2 [Barry_Boehm]
    Leaf2 = 26,
    ///Reliable Data Protocol [RFC908][Bob_Hinden]
    Rdp = 27,
    ///Internet Reliable Transaction [RFC938][Trudy_Miller]
    Irtp = 28,
    ///ISO Transport Protocol Class 4 [RFC905][<mystery contact>]
    IsoTp4 = 29,
    ///Bulk Data Transfer Protocol [RFC969][David_Clark]
    NetBlt = 30,
    ///MFE Network Services Protocol [Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.][Barry_Howard]
    MfeNsp = 31,
    ///MERIT Internodal Protocol [Hans_Werner_Braun]
    MeritInp = 32,
    ///Datagram Congestion Control Protocol [RFC4340]
    Dccp = 33,
    ///Third Party Connect Protocol [Stuart_A_Friedberg]
    ThirdPartyConnectProtocol = 34,
    ///Inter-Domain Policy Routing Protocol [Martha_Steenstrup]
    Idpr = 35,
    ///XTP [Greg_Chesson]
    Xtp = 36,
    ///Datagram Delivery Protocol [Wesley_Craig]
    Ddp = 37,
    ///IDPR Control Message Transport Proto [Martha_Steenstrup]
    IdprCmtp = 38,
    ///TP++ Transport Protocol [Dirk_Fromhein]
    TpPlusPlus = 39,
    ///IL Transport Protocol [Dave_Presotto]
    Il = 40,
    ///IPv6 encapsulation [RFC2473]
    Ipv6 = 41,
    ///Source Demand Routing Protocol [Deborah_Estrin]
    Sdrp = 42,
    ///Routing Header for IPv6 [Steve_Deering]
    IPv6RouteHeader = 43,
    ///Fragment Header for IPv6 [Steve_Deering]
    IPv6FragmentationHeader = 44,
    ///Inter-Domain Routing Protocol [Sue_Hares]
    Idrp = 45,
    ///Reservation Protocol [RFC2205][RFC3209][Bob_Braden]
    Rsvp = 46,
    ///Generic Routing Encapsulation [RFC2784][Tony_Li]
    Gre = 47,
    ///Dynamic Source Routing Protocol [RFC4728]
    Dsr = 48,
    ///BNA [Gary Salamon]
    Bna = 49,
    ///Encap Security Payload [RFC4303]
    IPv6EncapSecurityPayload = 50,
    ///Authentication Header [RFC4302]
    IPv6AuthenticationHeader = 51,
    ///Integrated Net Layer Security  TUBA [K_Robert_Glenn]
    Inlsp = 52,
    ///IP with Encryption (deprecated) [John_Ioannidis]
    Swipe = 53,
    ///NBMA Address Resolution Protocol [RFC1735]
    Narp = 54,
    ///IP Mobility [Charlie_Perkins]
    Mobile = 55,
    ///Transport Layer Security Protocol using Kryptonet key management [Christer_Oberg]
    Tlsp = 56,
    ///SKIP [Tom_Markson]
    Skip = 57,
    ///ICMP for IPv6 [RFC8200]
    IPv6Icmp = 58,
    ///No Next Header for IPv6 [RFC8200]
    IPv6NoNextHeader = 59,
    ///Destination Options for IPv6 [RFC8200]
    IPv6DestinationOptions = 60,
    ///any host internal protocol [Internet_Assigned_Numbers_Authority]
    AnyHostInternalProtocol = 61,
    ///CFTP [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.][Harry_Forsdick]
    Cftp = 62,
    ///any local network [Internet_Assigned_Numbers_Authority]
    AnyLocalNetwork = 63,
    ///SATNET and Backroom EXPAK [Steven_Blumenthal]
    SatExpak = 64,
    ///Kryptolan [Paul Liu]
    Krytolan = 65,
    ///MIT Remote Virtual Disk Protocol [Michael_Greenwald]
    Rvd = 66,
    ///Internet Pluribus Packet Core [Steven_Blumenthal]
    Ippc = 67,
    ///any distributed file system [Internet_Assigned_Numbers_Authority]
    AnyDistributedFileSystem = 68,
    ///SATNET Monitoring [Steven_Blumenthal]
    SatMon = 69,
    ///VISA Protocol [Gene_Tsudik]
    Visa = 70,
    ///Internet Packet Core Utility [Steven_Blumenthal]
    Ipcv = 71,
    ///Computer Protocol Network Executive [David Mittnacht]
    Cpnx = 72,
    ///Computer Protocol Heart Beat [David Mittnacht]
    Cphb = 73,
    ///Wang Span Network [Victor Dafoulas]
    Wsn = 74,
    ///Packet Video Protocol [Steve_Casner]
    Pvp = 75,
    ///Backroom SATNET Monitoring [Steven_Blumenthal]
    BrSatMon = 76,
    ///SUN ND PROTOCOL-Temporary [William_Melohn]
    SunNd = 77,
    ///WIDEBAND Monitoring [Steven_Blumenthal]
    WbMon = 78,
    ///WIDEBAND EXPAK [Steven_Blumenthal]
    WbExpak = 79,
    ///ISO Internet Protocol [Marshall_T_Rose]
    IsoIp = 80,
    ///VMTP [Dave_Cheriton]
    Vmtp = 81,
    ///SECURE-VMTP [Dave_Cheriton]
    SecureVmtp = 82,
    ///VINES [Brian Horn]
    Vines = 83,
    ///Transaction Transport Protocol or Internet Protocol Traffic Manager [Jim_Stevens]
    TtpOrIptm = 84,
    ///NSFNET-IGP [Hans_Werner_Braun]
    NsfnetIgp = 85,
    ///Dissimilar Gateway Protocol [M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.][Mike_Little]
    Dgp = 86,
    ///TCF [Guillermo_A_Loyola]
    Tcf = 87,
    ///EIGRP [RFC7868]
    Eigrp = 88,
    ///OSPFIGP [RFC1583][RFC2328][RFC5340][John_Moy]
    Ospfigp = 89,
    ///Sprite RPC Protocol [Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.][Bruce Willins]
    SpriteRpc = 90,
    ///Locus Address Resolution Protocol [Brian Horn]
    Larp = 91,
    ///Multicast Transport Protocol [Susie_Armstrong]
    Mtp = 92,
    ///AX.25 Frames [Brian_Kantor]
    Ax25 = 93,
    ///IP-within-IP Encapsulation Protocol [John_Ioannidis]
    Ipip = 94,
    ///Mobile Internetworking Control Pro. (deprecated) [John_Ioannidis]
    Micp = 95,
    ///Semaphore Communications Sec. Pro. [Howard_Hart]
    SccSp = 96,
    ///Ethernet-within-IP Encapsulation [RFC3378]
    EtherIp = 97,
    ///Encapsulation Header [RFC1241][Robert_Woodburn]
    Encap = 98,
    ///GMTP [[RXB5]]
    Gmtp = 100,
    ///Ipsilon Flow Management Protocol [Bob_Hinden][November 1995, 1997.]
    Ifmp = 101,
    ///PNNI over IP [Ross_Callon]
    Pnni = 102,
    ///Protocol Independent Multicast [RFC7761][Dino_Farinacci]
    Pim = 103,
    ///ARIS [Nancy_Feldman]
    Aris = 104,
    ///SCPS [Robert_Durst]
    Scps = 105,
    ///QNX [Michael_Hunter]
    Qnx = 106,
    ///Active Networks [Bob_Braden]
    ActiveNetworks = 107,
    ///IP Payload Compression Protocol [RFC2393]
    IpComp = 108,
    ///Sitara Networks Protocol [Manickam_R_Sridhar]
    SitraNetworksProtocol = 109,
    ///Compaq Peer Protocol [Victor_Volpe]
    CompaqPeer = 110,
    ///IPX in IP [CJ_Lee]
    IpxInIp = 111,
    ///Virtual Router Redundancy Protocol [RFC5798]
    Vrrp = 112,
    ///PGM Reliable Transport Protocol [Tony_Speakman]
    Pgm = 113,
    ///any 0-hop protocol [Internet_Assigned_Numbers_Authority]
    AnyZeroHopProtocol = 114,
    ///Layer Two Tunneling Protocol [RFC3931][Bernard_Aboba]
    Layer2TunnelingProtocol = 115,
    ///D-II Data Exchange (DDX) [John_Worley]
    Ddx = 116,
    ///Interactive Agent Transfer Protocol [John_Murphy]
    Iatp = 117,
    ///Schedule Transfer Protocol [Jean_Michel_Pittet]
    Stp = 118,
    ///SpectraLink Radio Protocol [Mark_Hamilton]
    Srp = 119,
    ///UTI [Peter_Lothberg]
    Uti = 120,
    ///Simple Message Protocol [Leif_Ekblad]
    SimpleMessageProtocol = 121,
    ///Simple Multicast Protocol (deprecated) [Jon_Crowcroft][draft-perlman-simple-multicast]
    Sm = 122,
    ///Performance Transparency Protocol [Michael_Welzl]
    Ptp = 123,
    ///ISIS over IPv4 [Tony_Przygienda]
    IsisOverIpv4 = 124,
    ///FIRE [Criag_Partridge]
    Fire = 125,
    ///Combat Radio Transport Protocol [Robert_Sautter]
    Crtp = 126,
    ///Combat Radio User Datagram [Robert_Sautter]
    Crudp = 127,
    ///SSCOPMCE [Kurt_Waber]
    Sscopmce = 128,
    ///IPLT [[Hollbach]]
    Iplt = 129,
    ///Secure Packet Shield [Bill_McIntosh]
    Sps = 130,
    ///Private IP Encapsulation within IP [Bernhard_Petri]
    Pipe = 131,
    ///Stream Control Transmission Protocol [Randall_R_Stewart]
    Sctp = 132,
    ///Fibre Channel [Murali_Rajagopal][RFC6172]
    Fc = 133,
    ///RSVP-E2E-IGNORE [RFC3175]
    RsvpE2eIgnore = 134,
    ///MobilityHeader [RFC6275]
    MobilityHeader = 135,
    ///UDPLite [RFC3828]
    UdpLite = 136,
    /// [RFC4023]
    MplsInIp = 137,
    ///MANET Protocols [RFC5498]
    Manet = 138,
    ///Host Identity Protocol [RFC7401]
    Hip = 139,
    ///Shim6 Protocol [RFC5533]
    Shim6 = 140,
    ///Wrapped Encapsulating Security Payload [RFC5840]
    Wesp = 141,
    ///Robust Header Compression [RFC5858]
    Rohc = 142
}

fn max_check_u8(value: u8, max: u8, field: ErrorField) -> Result<(), WriteError> {
    if value <= max {
        Ok(())
    } else {
        Err(WriteError::ValueU8TooLarge{ value: value, max: max, field: field })
    }
}
fn max_check_u16(value: u16, max: u16, field: ErrorField) -> Result<(), WriteError> {
    if value <= max {
        Ok(())
    } else {
        Err(WriteError::ValueU16TooLarge{ value: value, max: max, field: field })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ether_test_convert() {
        use super::*;
        use EtherType::*;

        assert_eq!(0x0800, Ipv4 as u16);
        assert_eq!(0x86dd, Ipv6 as u16);
        assert_eq!(0x0806, Arp as u16);
        assert_eq!(0x0842, WakeOnLan as u16);
        assert_eq!(0x8100, VlanTaggedFrame as u16);
        assert_eq!(0x9100, VlanDoubleTaggedFrame as u16);

        assert_eq!(EtherType::from_u16(0x0800), Some(Ipv4));
        assert_eq!(EtherType::from_u16(0x86dd), Some(Ipv6));
        assert_eq!(EtherType::from_u16(0x0806), Some(Arp));
        assert_eq!(EtherType::from_u16(0x0842), Some(WakeOnLan));
        assert_eq!(EtherType::from_u16(0x8100), Some(VlanTaggedFrame));
        assert_eq!(EtherType::from_u16(0x9100), Some(VlanDoubleTaggedFrame));
    }
    #[test]
    fn readwrite_ethernet2_header() {
        use super::*;
        use std::io::Cursor;
        
        let input = Ethernet2Header{
            destination: [1,2,3,4,5,6],
            source: [10,11,12,13,14,15],
            ether_type: 0x0800
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        buffer.write_ethernet2_header(&input).unwrap();
        assert_eq!(14, buffer.len());
        //deserialize
        let result = {
            let mut cursor = Cursor::new(&buffer);
            cursor.read_ethernet2_header().unwrap()
        };
        //check equivalence
        assert_eq!(input, result);
    }
    #[test]
    fn readwrite_vlan_tagging_header() {
        use super::*;
        use std::io::Cursor;
        
        let input = VlanTaggingHeader {
            ether_type: EtherType::Ipv4 as u16,
            priority_code_point: 2,
            drop_eligible_indicator: true,
            vlan_identifier: 1234,
        };

        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(4);
        buffer.write_vlan_tagging_header(&input).unwrap();
        assert_eq!(4, buffer.len());

        //deserialize
        let mut cursor = Cursor::new(&buffer);
        let result = cursor.read_vlan_tagging_header().unwrap();
        assert_eq!(4, cursor.position());

        //check equivalence
        assert_eq!(input, result);
    }
    #[test]
    fn write_vlan_tagging_header_errors() {
        use super::*;
        use super::WriteError::*;
        use super::ErrorField::*;
        fn base() -> VlanTaggingHeader {
            VlanTaggingHeader {
                ether_type: EtherType::Ipv4 as u16,
                priority_code_point: 2,
                drop_eligible_indicator: true,
                vlan_identifier: 1234,
            }
        };

        fn test_write(input: &VlanTaggingHeader) -> Result<(), WriteError> {
            let mut buffer: Vec<u8> = Vec::new();
            let result = buffer.write_vlan_tagging_header(input);
            assert_eq!(0, buffer.len());
            result
        };

        //priority_code_point
        match test_write(&{
            let mut value = base();
            value.priority_code_point = 4;
            value
        }) {
            Err(ValueU8TooLarge{value: 4, max: 3, field: VlanTagPriorityCodePoint}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }

        //vlan_identifier
        match test_write(&{
            let mut value = base();
            value.vlan_identifier = 0x1000;
            value
        }) {
            Err(ValueU16TooLarge{value: 0x1000, max: 0xFFF, field: VlanTagVlanId}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
    }
    #[test]
    fn read_ip_header_ipv4() {
        use super::*;
        use std::io::Cursor;

        let input = Ipv4Header {
            header_length: 10,
            differentiated_services_code_point: 42,
            explicit_congestion_notification: 3,
            total_length: 1234,
            identification: 4321,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 4367,
            time_to_live: 8,
            protocol: 1,
            header_checksum: 2345,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv4_header(&input).unwrap();
        assert_eq!(20, buffer.len());

        //deserialize
        let mut cursor = Cursor::new(&buffer);
        let result = cursor.read_ip_header().unwrap();
        assert_eq!(20, cursor.position());

        match result {
            IpHeader::Version4(result) => assert_eq!(input, result),
            value => assert!(false, format!("Expected IpHeaderV4 but received {:?}", value))
        }
    }
    #[test]
    fn read_ip_header_ipv6() {
        use super::*;
        use std::io::Cursor;
        let input = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv6_header(&input).unwrap();
        assert_eq!(40, buffer.len());

        //deserialize
        let mut cursor = Cursor::new(&buffer);
        let result = cursor.read_ip_header().unwrap();
        assert_eq!(40, cursor.position());

        match result {
            IpHeader::Version6(result) => assert_eq!(input, result),
            value => assert!(false, format!("Expected IpHeaderV6 but received {:?}", value))
        }
    }
    #[test]
    fn readwrite_ipv4_header() {
        use super::*;
        use std::io::Cursor;

        let input = Ipv4Header {
            header_length: 10,
            differentiated_services_code_point: 42,
            explicit_congestion_notification: 3,
            total_length: 1234,
            identification: 4321,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 4367,
            time_to_live: 8,
            protocol: 1,
            header_checksum: 2345,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv4_header(&input).unwrap();
        assert_eq!(20, buffer.len());

        //deserialize
        let mut cursor = Cursor::new(&buffer);
        let result = cursor.read_ipv4_header().unwrap();
        assert_eq!(20, cursor.position());

        //check equivalence
        assert_eq!(input, result);
    }
    #[test]
    fn write_ipv4_header_errors() {
        use super::*;
        use super::WriteError::*;
        use super::ErrorField::*;
        fn base() -> Ipv4Header {
            Ipv4Header{
                header_length: 10,
                differentiated_services_code_point: 42,
                explicit_congestion_notification: 3,
                total_length: 1234,
                identification: 4321,
                dont_fragment: true,
                more_fragments: false,
                fragments_offset: 4367,
                time_to_live: 8,
                protocol: 1,
                header_checksum: 2345,
                source: [192, 168, 1, 1],
                destination: [212, 10, 11, 123]
            }
        };

        fn test_write(input: &Ipv4Header) -> Result<(), WriteError> {
            let mut buffer: Vec<u8> = Vec::new();
            let result = buffer.write_ipv4_header(input);
            assert_eq!(0, buffer.len());
            result
        };
        //header_length
        match test_write(&{
            let mut value = base();
            value.header_length = 0x1f;
            value
        }) {
            Err(ValueU8TooLarge{value: 0x1f, max: 0xf, field: Ipv4HeaderLength}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
        //dscp
        match test_write(&{
            let mut value = base();
            value.differentiated_services_code_point = 0x40;
            value
        }) {
            Err(ValueU8TooLarge{value: 0x40, max: 0x3f, field: Ipv4Dscp}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
        //ecn
        match test_write(&{
            let mut value = base();
            value.explicit_congestion_notification = 0x4;
            value
        }) {
            Err(ValueU8TooLarge{value: 0x4, max: 0x3, field: Ipv4Ecn}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
        //fragmentation offset
        match test_write(&{
            let mut value = base();
            value.fragments_offset = 0x2000;
            value
        }) {
            Err(ValueU16TooLarge{value: 0x2000, max: 0x1FFF, field: Ipv4FragmentsOffset}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
    }
    #[test]
    fn read_ipv4_error_header() {
        use super::*;
        let buffer: [u8;20] = [0;20];
        let mut cursor = io::Cursor::new(&buffer);
        let result = cursor.read_ipv4_header();
        match result {
            Err(ReadError::Ipv4UnexpectedVersion(0)) => {},
            _ => assert!(false, format!("Expected ipv 4 version error but received {:?}", result))
        }
    } 
    #[test]
    fn readwrite_ipv6_header() {
        use super::*;
        use std::io::Cursor;

        let input = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv6_header(&input).unwrap();
        //deserialize
        let result = {
            let mut cursor = Cursor::new(&buffer);
            cursor.read_ipv6_header().unwrap()
        };
        //check equivalence
        assert_eq!(input, result);
    }
    #[test]
    fn write_ipv6_header_errors() {
        use super::*;
        use super::WriteError::*;
        use super::ErrorField::*;
        fn base() -> Ipv6Header {
            Ipv6Header {
                traffic_class: 1,
                flow_label: 0x201806,
                payload_length: 0x8021,
                next_header: 30,
                hop_limit: 40,
                source: [1, 2, 3, 4, 5, 6, 7, 8,
                         9,10,11,12,13,14,15,16],
                destination: [21,22,23,24,25,26,27,28,
                              29,30,31,32,33,34,35,36]
            }
        };

        fn test_write(input: &Ipv6Header) -> Result<(), WriteError> {
            let mut buffer: Vec<u8> = Vec::with_capacity(20);
            buffer.write_ipv6_header(input)
        };
        //flow label
        match test_write(&{
            let mut value = base();
            value.flow_label = 0x100000;
            value
        }) {
            Err(ValueU32TooLarge{value: 0x100000, max: 0xFFFFF, field: Ipv6FlowLabel}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
    }
    #[test]
    fn read_ipv6_error_header() {
        use super::*;
        let buffer: [u8;20] = [0;20];
        let mut cursor = io::Cursor::new(&buffer);
        let result = cursor.read_ipv6_header();
        match result {
            Err(ReadError::Ipv6UnexpectedVersion(0)) => {},
            _ => assert!(false, format!("Expected ipv 6 version error but received {:?}", result))
        }
    }
    #[test]
    fn skip_ipv6_header_extension() {
        use super::*;
        use std::io::Cursor;
        {
            let buffer: [u8; 8] = [0;8];
            let mut cursor = Cursor::new(&buffer);
            match cursor.skip_ipv6_header_extension() {
                Ok(0) => {},
                value => assert!(false, format!("Expected Ok(0) but received {:?}", value))
            }
            assert_eq!(8, cursor.position());
        }
        {
            let buffer: [u8; 8*3] = [
                4,2,0,0, 0,0,0,0,
                0,0,0,0, 0,0,0,0,
                0,0,0,0, 0,0,0,0,
            ];
            let mut cursor = Cursor::new(&buffer);
            match cursor.skip_ipv6_header_extension() {
                Ok(4) => {},
                value => assert!(false, format!("Expected Ok(4) but received {:?}", value))
            }
            assert_eq!(8*3, cursor.position());
        }
    }
    #[test]
    fn skip_all_ipv6_header_extensions() {
        use super::*;
        use io::Cursor;
        //extension header values
        use IpTrafficClass::*;
        //based on RFC 8200 4.1. Extension Header Order
        const EXTENSION_IDS: [u8;7] = [
            IPv6HeaderHopByHop as u8,
            IPv6DestinationOptions as u8,
            IPv6RouteHeader as u8,
            IPv6FragmentationHeader as u8,
            IPv6AuthenticationHeader as u8,
            IPv6EncapSecurityPayload as u8,
            IPv6DestinationOptions as u8
        ];
        const UDP: u8 = Udp as u8;

        //no & single skipping
        {
            
            let buffer: [u8; 8*3] = [
                UDP,2,0,0, 0,0,0,0, //set next to udp
                0,0,0,0,   0,0,0,0,
                0,0,0,0,   0,0,0,0,
            ];

            for i_as16 in 0..((u8::max_value() as u16) + 1) {
                let i = i_as16 as u8; //note: I would prefer to use the inclusive range ..= but this feature is not yet marked as stable -> replace when stable
                let mut cursor = Cursor::new(&buffer);
                let result = cursor.skip_all_ipv6_header_extensions(i);

                match EXTENSION_IDS.iter().find(|&&x| x == i) {
                    Some(_) => {
                        //ipv6 header extension -> expect skip
                        match result {
                            Ok(UDP) => {},
                            _ => assert!(false, format!("exepected udp as next traffic_class but received {:?}", result))
                        }
                        assert_eq!(buffer.len(), cursor.position() as usize);
                    },
                    None => {
                        //non ipv6 header expect no read movement and direct return
                        match result {
                            Ok(next) => assert_eq!(i, next),
                            _ => assert!(false, format!("exepected {} as next traffic_class but received {:?}", i, result))
                        }
                        assert_eq!(0, cursor.position());
                    }
                }
            }

        }
        //skip 7 (max)
        {
            let buffer = vec![
                EXTENSION_IDS[1],0,0,0, 0,0,0,0,
                EXTENSION_IDS[2],1,0,0, 0,0,0,0,
                0,0,0,0,                0,0,0,0,
                EXTENSION_IDS[3],0,0,0, 0,0,0,0,
                EXTENSION_IDS[4],1,0,0, 0,0,0,0,

                0,0,0,0,                0,0,0,0,
                EXTENSION_IDS[5],0,0,0, 0,0,0,0,
                EXTENSION_IDS[6],0,0,0, 0,0,0,0,
                UDP,2,0,0, 0,0,0,0,

                0,0,0,0,   0,0,0,0,
                0,0,0,0,   0,0,0,0,
            ];
            let mut cursor = Cursor::new(&buffer);
            let result = cursor.skip_all_ipv6_header_extensions(EXTENSION_IDS[0]);
            match result {
                Ok(UDP) => {},
                result => assert!(false, format!("exepected udp as next traffic_class but received {:?}", result)) 
            }
            assert_eq!(buffer.len(), cursor.position() as usize);
        }
        //trigger "too many" error
        {
            let buffer = vec![
                EXTENSION_IDS[1],0,0,0, 0,0,0,0,
                EXTENSION_IDS[2],0,0,0, 0,0,0,0,
                EXTENSION_IDS[3],0,0,0, 0,0,0,0,
                EXTENSION_IDS[4],0,0,0, 0,0,0,0,
                EXTENSION_IDS[5],0,0,0, 0,0,0,0,
                EXTENSION_IDS[6],0,0,0, 0,0,0,0,
                EXTENSION_IDS[1],0,0,0, 0,0,0,0,
            ];
            let mut cursor = Cursor::new(&buffer);
            let result = cursor.skip_all_ipv6_header_extensions(EXTENSION_IDS[0]);
            match result {
                Err(ReadError::Ipv6TooManyHeaderExtensions) => {},
                result => assert!(false, format!("exepected error Ipv6TooManyHeaderExtensions but received {:?}", result)) 
            }
        }
    }
}
