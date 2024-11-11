/// Represents an ARP protocol hardware identifier.
///
/// You can access the underlying `u16` value by using `.0` and any `u16`
/// can be converted to an `ArpHardwareId`:
///
/// ```
/// use etherparse::ArpHardwareId;
///
/// assert_eq!(ArpHardwareId::ETHER.0, 0x0001);
/// assert_eq!(ArpHardwareId::ETHER, ArpHardwareId(0x0001));
///
/// // convert to ArpHardwareId using the from & into trait
/// let arp_hrd_id: ArpHardwareId = 0x0001.into();
/// assert_eq!(ArpHardwareId::ETHER, arp_hrd_id);
///
/// // convert to u16 using the from & into trait
/// let num: u16 = ArpHardwareId::ETHER.into();
/// assert_eq!(0x0001, num);
/// ```
///
#[derive(Clone, Copy, Eq, PartialEq, Default, Hash)]
pub struct ArpHardwareId(pub u16);

impl ArpHardwareId {
    // Numbers sourced from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/if_arp.h?id=e33c4963bf536900f917fb65a687724d5539bc21

    pub const NETROM: ArpHardwareId = Self(0);
    pub const ETHERNET: ArpHardwareId = Self(1);
    pub const EETHER: ArpHardwareId = Self(2);
    pub const AX25: ArpHardwareId = Self(3);
    pub const PRONET: ArpHardwareId = Self(4);
    pub const CHAOS: ArpHardwareId = Self(5);
    pub const IEEE802: ArpHardwareId = Self(6);
    pub const ARCNET: ArpHardwareId = Self(7);
    pub const APPLETLK: ArpHardwareId = Self(8);
    pub const DLCI: ArpHardwareId = Self(15);
    pub const ATM: ArpHardwareId = Self(19);
    pub const METRICOM: ArpHardwareId = Self(23);
    pub const IEEE1394: ArpHardwareId = Self(24);
    pub const EUI64: ArpHardwareId = Self(27);
    pub const INFINIBAND: ArpHardwareId = Self(32);
    pub const SLIP: ArpHardwareId = Self(256);
    pub const CSLIP: ArpHardwareId = Self(257);
    pub const SLIP6: ArpHardwareId = Self(258);
    pub const CSLIP6: ArpHardwareId = Self(259);
    pub const RSRVD: ArpHardwareId = Self(260);
    pub const ADAPT: ArpHardwareId = Self(264);
    pub const ROSE: ArpHardwareId = Self(270);
    pub const X25: ArpHardwareId = Self(271);
    pub const HWX25: ArpHardwareId = Self(272);
    pub const CAN: ArpHardwareId = Self(280);
    pub const PPP: ArpHardwareId = Self(512);
    pub const CISCO_HDLC: ArpHardwareId = Self(513);
    pub const LAPB: ArpHardwareId = Self(516);
    pub const DDCMP: ArpHardwareId = Self(517);
    pub const RAWHDLC: ArpHardwareId = Self(518);
    pub const RAWIP: ArpHardwareId = Self(519);
    pub const TUNNEL: ArpHardwareId = Self(768);
    pub const TUNNEL6: ArpHardwareId = Self(769);
    pub const FRAD: ArpHardwareId = Self(770);
    pub const SKIP: ArpHardwareId = Self(771);
    pub const LOOPBACK: ArpHardwareId = Self(772);
    pub const LOCALTLK: ArpHardwareId = Self(773);
    pub const FDDI: ArpHardwareId = Self(774);
    pub const BIF: ArpHardwareId = Self(775);
    pub const SIT: ArpHardwareId = Self(776);
    pub const IPDDP: ArpHardwareId = Self(777);
    pub const IPGRE: ArpHardwareId = Self(778);
    pub const PIMREG: ArpHardwareId = Self(779);
    pub const HIPPI: ArpHardwareId = Self(780);
    pub const ASH: ArpHardwareId = Self(781);
    pub const ECONET: ArpHardwareId = Self(782);
    pub const IRDA: ArpHardwareId = Self(783);
    pub const FCPP: ArpHardwareId = Self(784);
    pub const FCAL: ArpHardwareId = Self(785);
    pub const FCPL: ArpHardwareId = Self(786);
    pub const FCFABRIC: ArpHardwareId = Self(787);
    pub const IEEE802_TR: ArpHardwareId = Self(800);
    pub const IEEE80211: ArpHardwareId = Self(801);
    pub const IEEE80211_PRISM: ArpHardwareId = Self(802);
    pub const IEEE80211_RADIOTAP: ArpHardwareId = Self(803);
    pub const IEEE802154: ArpHardwareId = Self(804);
    pub const IEEE802154_MONITOR: ArpHardwareId = Self(805);
    pub const PHONET: ArpHardwareId = Self(820);
    pub const PHONET_PIPE: ArpHardwareId = Self(821);
    pub const CAIF: ArpHardwareId = Self(822);
    pub const IP6GRE: ArpHardwareId = Self(823);
    pub const NETLINK: ArpHardwareId = Self(824);
    pub const IPV6LOWPAN: ArpHardwareId = Self(825);
    pub const VSOCKMON: ArpHardwareId = Self(826);
    pub const VOID: ArpHardwareId = Self(0xFFFF);
    pub const NONE: ArpHardwareId = Self(0xFFFE);
}

impl From<u16> for ArpHardwareId {
    #[inline]
    fn from(val: u16) -> Self {
        ArpHardwareId(val)
    }
}

impl From<ArpHardwareId> for u16 {
    #[inline]
    fn from(val: ArpHardwareId) -> Self {
        val.0
    }
}

impl core::fmt::Display for ArpHardwareId {
    // Names sourced from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/if_arp.h?id=e33c4963bf536900f917fb65a687724d5539bc21

    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::NETROM => write!(f, "{} (from KA9Q: NET/ROM pseudo)", self.0),
            Self::ETHERNET => write!(f, "{} (Ethernet 10Mbps)", self.0),
            Self::EETHER => write!(f, "{} (Experimental Ethernet)", self.0),
            Self::AX25 => write!(f, "{} (AX.25 Level 2)", self.0),
            Self::PRONET => write!(f, "{} (PROnet token ring)", self.0),
            Self::CHAOS => write!(f, "{} (Chaosnet)", self.0),
            Self::IEEE802 => write!(f, "{} (IEEE 802.2 Ethernet/TR/TB)", self.0),
            Self::ARCNET => write!(f, "{} (ARCnet)", self.0),
            Self::APPLETLK => write!(f, "{} (APPLEtalk)", self.0),
            Self::DLCI => write!(f, "{} (Frame Relay DLCI)", self.0),
            Self::ATM => write!(f, "{} (ATM)", self.0),
            Self::METRICOM => write!(f, "{} (Metricom STRIP (new IANA id))", self.0),
            Self::IEEE1394 => write!(f, "{} (IEEE 1394 IPv4 - RFC 2734)", self.0),
            Self::EUI64 => write!(f, "{} (EUI-64)", self.0),
            Self::INFINIBAND => write!(f, "{} (InfiniBand)", self.0),
            Self::SLIP => write!(f, "{} (SLIP)", self.0),
            Self::CSLIP => write!(f, "{} (CSLIP)", self.0),
            Self::SLIP6 => write!(f, "{} (SLIP6)", self.0),
            Self::CSLIP6 => write!(f, "{} (CSLIP6)", self.0),
            Self::RSRVD => write!(f, "{} (Notional KISS type)", self.0),
            Self::ADAPT => write!(f, "{} (ADAPT)", self.0),
            Self::ROSE => write!(f, "{} (ROSE)", self.0),
            Self::X25 => write!(f, "{} (CCITT X.25)", self.0),
            Self::HWX25 => write!(f, "{} (Boards with X.25 in firmware)", self.0),
            Self::CAN => write!(f, "{} (Controller Area Network)", self.0),
            Self::PPP => write!(f, "{} (PPP)", self.0),
            Self::CISCO_HDLC => write!(f, "{} (Cisco HDLC)", self.0),
            Self::LAPB => write!(f, "{} (LAPB)", self.0),
            Self::DDCMP => write!(f, "{} (Digital's DDCMP protocol)", self.0),
            Self::RAWHDLC => write!(f, "{} (Raw HDLC)", self.0),
            Self::RAWIP => write!(f, "{} (Raw IP)", self.0),
            Self::TUNNEL => write!(f, "{} (IPIP tunnel)", self.0),
            Self::TUNNEL6 => write!(f, "{} (IP6IP6 tunnel)", self.0),
            Self::FRAD => write!(f, "{} (Frame Relay Access Device)", self.0),
            Self::SKIP => write!(f, "{} (SKIP vif)", self.0),
            Self::LOOPBACK => write!(f, "{} (Loopback device)", self.0),
            Self::LOCALTLK => write!(f, "{} (Localtalk device)", self.0),
            Self::FDDI => write!(f, "{} (Fiber Distributed Data Interface)", self.0),
            Self::BIF => write!(f, "{} (AP1000 BIF)", self.0),
            Self::SIT => write!(f, "{} (sit0 device - IPv6-in-IPv4)", self.0),
            Self::IPDDP => write!(f, "{} (IP over DDP tunneller)", self.0),
            Self::IPGRE => write!(f, "{} (GRE over IP)", self.0),
            Self::PIMREG => write!(f, "{} (PIMSM register interface)", self.0),
            Self::HIPPI => write!(f, "{} (High Performance Parallel Interface)", self.0),
            Self::ASH => write!(f, "{} (Nexus 64Mbps Ash)", self.0),
            Self::ECONET => write!(f, "{} (Acorn Econet)", self.0),
            Self::IRDA => write!(f, "{} (Linux-IrDA)", self.0),
            Self::FCPP => write!(f, "{} (Point to point fibrechannel)", self.0),
            Self::FCAL => write!(f, "{} (Fibrechannel arbitrated loop)", self.0),
            Self::FCPL => write!(f, "{} (Fibrechannel public loop)", self.0),
            Self::FCFABRIC => write!(f, "{} (Fibrechannel fabric)", self.0),
            Self::IEEE802_TR => write!(f, "{} (Magic type ident for TR)", self.0),
            Self::IEEE80211 => write!(f, "{} (IEEE 802.11)", self.0),
            Self::IEEE80211_PRISM => write!(f, "{} (IEEE 802.11 + Prism2 header)", self.0),
            Self::IEEE80211_RADIOTAP => write!(f, "{} (IEEE 802.11 + radiotap header)", self.0),
            Self::IEEE802154 => write!(f, "{} (IEEE 802.15.4)", self.0),
            Self::IEEE802154_MONITOR => write!(f, "{} (IEEE 802.15.4 network monitor)", self.0),
            Self::PHONET => write!(f, "{} (PhoNet media type)", self.0),
            Self::PHONET_PIPE => write!(f, "{} (PhoNet pipe header)", self.0),
            Self::CAIF => write!(f, "{} (CAIF media type)", self.0),
            Self::IP6GRE => write!(f, "{} (GRE over IPv6)", self.0),
            Self::NETLINK => write!(f, "{} (Netlink header)", self.0),
            Self::IPV6LOWPAN => write!(f, "{} (IPv6 over LoWPAN)", self.0),
            Self::VSOCKMON => write!(f, "{} (Vsock monitor header)", self.0),
            Self::VOID => write!(f, "{:#06X} (Void type, nothing is known)", self.0),
            Self::NONE => write!(f, "{:#06X} (zero header length)", self.0),
            _ => write!(f, "{:#06X}", self.0),
        }
    }
}

impl core::fmt::Debug for ArpHardwareId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self, f)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn to_u16() {
        assert_eq!(0, u16::from(ArpHardwareId::NETROM));
        assert_eq!(1, u16::from(ArpHardwareId::ETHERNET));
        assert_eq!(2, u16::from(ArpHardwareId::EETHER));
        assert_eq!(3, u16::from(ArpHardwareId::AX25));
        assert_eq!(4, u16::from(ArpHardwareId::PRONET));
        assert_eq!(5, u16::from(ArpHardwareId::CHAOS));
        assert_eq!(6, u16::from(ArpHardwareId::IEEE802));
        assert_eq!(7, u16::from(ArpHardwareId::ARCNET));
        assert_eq!(8, u16::from(ArpHardwareId::APPLETLK));
        assert_eq!(15, u16::from(ArpHardwareId::DLCI));
        assert_eq!(19, u16::from(ArpHardwareId::ATM));
        assert_eq!(23, u16::from(ArpHardwareId::METRICOM));
        assert_eq!(24, u16::from(ArpHardwareId::IEEE1394));
        assert_eq!(27, u16::from(ArpHardwareId::EUI64));
        assert_eq!(32, u16::from(ArpHardwareId::INFINIBAND));

        assert_eq!(256, u16::from(ArpHardwareId::SLIP));
        assert_eq!(257, u16::from(ArpHardwareId::CSLIP));
        assert_eq!(258, u16::from(ArpHardwareId::SLIP6));
        assert_eq!(259, u16::from(ArpHardwareId::CSLIP6));
        assert_eq!(260, u16::from(ArpHardwareId::RSRVD));
        assert_eq!(264, u16::from(ArpHardwareId::ADAPT));
        assert_eq!(270, u16::from(ArpHardwareId::ROSE));
        assert_eq!(271, u16::from(ArpHardwareId::X25));
        assert_eq!(272, u16::from(ArpHardwareId::HWX25));
        assert_eq!(280, u16::from(ArpHardwareId::CAN));
        assert_eq!(512, u16::from(ArpHardwareId::PPP));
        assert_eq!(513, u16::from(ArpHardwareId::CISCO_HDLC));
        assert_eq!(516, u16::from(ArpHardwareId::LAPB));
        assert_eq!(517, u16::from(ArpHardwareId::DDCMP));
        assert_eq!(518, u16::from(ArpHardwareId::RAWHDLC));
        assert_eq!(519, u16::from(ArpHardwareId::RAWIP));

        assert_eq!(768, u16::from(ArpHardwareId::TUNNEL));
        assert_eq!(769, u16::from(ArpHardwareId::TUNNEL6));
        assert_eq!(770, u16::from(ArpHardwareId::FRAD));
        assert_eq!(771, u16::from(ArpHardwareId::SKIP));
        assert_eq!(772, u16::from(ArpHardwareId::LOOPBACK));
        assert_eq!(773, u16::from(ArpHardwareId::LOCALTLK));
        assert_eq!(774, u16::from(ArpHardwareId::FDDI));
        assert_eq!(775, u16::from(ArpHardwareId::BIF));
        assert_eq!(776, u16::from(ArpHardwareId::SIT));
        assert_eq!(777, u16::from(ArpHardwareId::IPDDP));
        assert_eq!(778, u16::from(ArpHardwareId::IPGRE));
        assert_eq!(779, u16::from(ArpHardwareId::PIMREG));
        assert_eq!(780, u16::from(ArpHardwareId::HIPPI));
        assert_eq!(781, u16::from(ArpHardwareId::ASH));
        assert_eq!(782, u16::from(ArpHardwareId::ECONET));
        assert_eq!(783, u16::from(ArpHardwareId::IRDA));

        assert_eq!(784, u16::from(ArpHardwareId::FCPP));
        assert_eq!(785, u16::from(ArpHardwareId::FCAL));
        assert_eq!(786, u16::from(ArpHardwareId::FCPL));
        assert_eq!(787, u16::from(ArpHardwareId::FCFABRIC));

        assert_eq!(800, u16::from(ArpHardwareId::IEEE802_TR));
        assert_eq!(801, u16::from(ArpHardwareId::IEEE80211));
        assert_eq!(802, u16::from(ArpHardwareId::IEEE80211_PRISM));
        assert_eq!(803, u16::from(ArpHardwareId::IEEE80211_RADIOTAP));
        assert_eq!(804, u16::from(ArpHardwareId::IEEE802154));
        assert_eq!(805, u16::from(ArpHardwareId::IEEE802154_MONITOR));

        assert_eq!(820, u16::from(ArpHardwareId::PHONET));
        assert_eq!(821, u16::from(ArpHardwareId::PHONET_PIPE));
        assert_eq!(822, u16::from(ArpHardwareId::CAIF));
        assert_eq!(823, u16::from(ArpHardwareId::IP6GRE));
        assert_eq!(824, u16::from(ArpHardwareId::NETLINK));
        assert_eq!(825, u16::from(ArpHardwareId::IPV6LOWPAN));
        assert_eq!(826, u16::from(ArpHardwareId::VSOCKMON));

        assert_eq!(0xFFFF, u16::from(ArpHardwareId::VOID));
        assert_eq!(0xFFFE, u16::from(ArpHardwareId::NONE));
    }

    #[test]
    fn from_u16() {
        assert_eq!(ArpHardwareId::from(0), ArpHardwareId::NETROM);
        assert_eq!(ArpHardwareId::from(1), ArpHardwareId::ETHERNET);
        assert_eq!(ArpHardwareId::from(2), ArpHardwareId::EETHER);
        assert_eq!(ArpHardwareId::from(3), ArpHardwareId::AX25);
        assert_eq!(ArpHardwareId::from(4), ArpHardwareId::PRONET);
        assert_eq!(ArpHardwareId::from(5), ArpHardwareId::CHAOS);
        assert_eq!(ArpHardwareId::from(6), ArpHardwareId::IEEE802);
        assert_eq!(ArpHardwareId::from(7), ArpHardwareId::ARCNET);
        assert_eq!(ArpHardwareId::from(8), ArpHardwareId::APPLETLK);
        assert_eq!(ArpHardwareId::from(15), ArpHardwareId::DLCI);
        assert_eq!(ArpHardwareId::from(19), ArpHardwareId::ATM);
        assert_eq!(ArpHardwareId::from(23), ArpHardwareId::METRICOM);
        assert_eq!(ArpHardwareId::from(24), ArpHardwareId::IEEE1394);
        assert_eq!(ArpHardwareId::from(27), ArpHardwareId::EUI64);
        assert_eq!(ArpHardwareId::from(32), ArpHardwareId::INFINIBAND);

        assert_eq!(ArpHardwareId::from(256), ArpHardwareId::SLIP);
        assert_eq!(ArpHardwareId::from(257), ArpHardwareId::CSLIP);
        assert_eq!(ArpHardwareId::from(258), ArpHardwareId::SLIP6);
        assert_eq!(ArpHardwareId::from(259), ArpHardwareId::CSLIP6);
        assert_eq!(ArpHardwareId::from(260), ArpHardwareId::RSRVD);
        assert_eq!(ArpHardwareId::from(264), ArpHardwareId::ADAPT);
        assert_eq!(ArpHardwareId::from(270), ArpHardwareId::ROSE);
        assert_eq!(ArpHardwareId::from(271), ArpHardwareId::X25);
        assert_eq!(ArpHardwareId::from(272), ArpHardwareId::HWX25);
        assert_eq!(ArpHardwareId::from(280), ArpHardwareId::CAN);
        assert_eq!(ArpHardwareId::from(512), ArpHardwareId::PPP);
        assert_eq!(ArpHardwareId::from(513), ArpHardwareId::CISCO_HDLC);
        assert_eq!(ArpHardwareId::from(516), ArpHardwareId::LAPB);
        assert_eq!(ArpHardwareId::from(517), ArpHardwareId::DDCMP);
        assert_eq!(ArpHardwareId::from(518), ArpHardwareId::RAWHDLC);
        assert_eq!(ArpHardwareId::from(519), ArpHardwareId::RAWIP);

        assert_eq!(ArpHardwareId::from(768), ArpHardwareId::TUNNEL);
        assert_eq!(ArpHardwareId::from(769), ArpHardwareId::TUNNEL6);
        assert_eq!(ArpHardwareId::from(770), ArpHardwareId::FRAD);
        assert_eq!(ArpHardwareId::from(771), ArpHardwareId::SKIP);
        assert_eq!(ArpHardwareId::from(772), ArpHardwareId::LOOPBACK);
        assert_eq!(ArpHardwareId::from(773), ArpHardwareId::LOCALTLK);
        assert_eq!(ArpHardwareId::from(774), ArpHardwareId::FDDI);
        assert_eq!(ArpHardwareId::from(775), ArpHardwareId::BIF);
        assert_eq!(ArpHardwareId::from(776), ArpHardwareId::SIT);
        assert_eq!(ArpHardwareId::from(777), ArpHardwareId::IPDDP);
        assert_eq!(ArpHardwareId::from(778), ArpHardwareId::IPGRE);
        assert_eq!(ArpHardwareId::from(779), ArpHardwareId::PIMREG);
        assert_eq!(ArpHardwareId::from(780), ArpHardwareId::HIPPI);
        assert_eq!(ArpHardwareId::from(781), ArpHardwareId::ASH);
        assert_eq!(ArpHardwareId::from(782), ArpHardwareId::ECONET);
        assert_eq!(ArpHardwareId::from(783), ArpHardwareId::IRDA);

        assert_eq!(ArpHardwareId::from(784), ArpHardwareId::FCPP);
        assert_eq!(ArpHardwareId::from(785), ArpHardwareId::FCAL);
        assert_eq!(ArpHardwareId::from(786), ArpHardwareId::FCPL);
        assert_eq!(ArpHardwareId::from(787), ArpHardwareId::FCFABRIC);

        assert_eq!(ArpHardwareId::from(800), ArpHardwareId::IEEE802_TR);
        assert_eq!(ArpHardwareId::from(801), ArpHardwareId::IEEE80211);
        assert_eq!(ArpHardwareId::from(802), ArpHardwareId::IEEE80211_PRISM);
        assert_eq!(ArpHardwareId::from(803), ArpHardwareId::IEEE80211_RADIOTAP);
        assert_eq!(ArpHardwareId::from(804), ArpHardwareId::IEEE802154);
        assert_eq!(ArpHardwareId::from(805), ArpHardwareId::IEEE802154_MONITOR);

        assert_eq!(ArpHardwareId::from(820), ArpHardwareId::PHONET);
        assert_eq!(ArpHardwareId::from(821), ArpHardwareId::PHONET_PIPE);
        assert_eq!(ArpHardwareId::from(822), ArpHardwareId::CAIF);
        assert_eq!(ArpHardwareId::from(823), ArpHardwareId::IP6GRE);
        assert_eq!(ArpHardwareId::from(824), ArpHardwareId::NETLINK);
        assert_eq!(ArpHardwareId::from(825), ArpHardwareId::IPV6LOWPAN);
        assert_eq!(ArpHardwareId::from(826), ArpHardwareId::VSOCKMON);

        assert_eq!(ArpHardwareId::from(0xFFFF), ArpHardwareId::VOID);
        assert_eq!(ArpHardwareId::from(0xFFFE), ArpHardwareId::NONE);
    }

    #[test]
    fn display_dbg() {
        let pairs = &[
            (ArpHardwareId::NETROM, "0 (from KA9Q: NET/ROM pseudo)"),
            (ArpHardwareId::ETHERNET, "1 (Ethernet 10Mbps)"),
            (ArpHardwareId::EETHER, "2 (Experimental Ethernet)"),
            (ArpHardwareId::AX25, "3 (AX.25 Level 2)"),
            (ArpHardwareId::PRONET, "4 (PROnet token ring)"),
            (ArpHardwareId::CHAOS, "5 (Chaosnet)"),
            (ArpHardwareId::IEEE802, "6 (IEEE 802.2 Ethernet/TR/TB)"),
            (ArpHardwareId::ARCNET, "7 (ARCnet)"),
            (ArpHardwareId::APPLETLK, "8 (APPLEtalk)"),
            (ArpHardwareId::DLCI, "15 (Frame Relay DLCI)"),
            (ArpHardwareId::ATM, "19 (ATM)"),
            (ArpHardwareId::METRICOM, "23 (Metricom STRIP (new IANA id))"),
            (ArpHardwareId::IEEE1394, "24 (IEEE 1394 IPv4 - RFC 2734)"),
            (ArpHardwareId::EUI64, "27 (EUI-64)"),
            (ArpHardwareId::INFINIBAND, "32 (InfiniBand)"),
            (ArpHardwareId::SLIP, "256 (SLIP)"),
            (ArpHardwareId::CSLIP, "257 (CSLIP)"),
            (ArpHardwareId::SLIP6, "258 (SLIP6)"),
            (ArpHardwareId::CSLIP6, "259 (CSLIP6)"),
            (ArpHardwareId::RSRVD, "260 (Notional KISS type)"),
            (ArpHardwareId::ADAPT, "264 (ADAPT)"),
            (ArpHardwareId::ROSE, "270 (ROSE)"),
            (ArpHardwareId::X25, "271 (CCITT X.25)"),
            (ArpHardwareId::HWX25, "272 (Boards with X.25 in firmware)"),
            (ArpHardwareId::CAN, "280 (Controller Area Network)"),
            (ArpHardwareId::PPP, "512 (PPP)"),
            (ArpHardwareId::CISCO_HDLC, "513 (Cisco HDLC)"),
            (ArpHardwareId::LAPB, "516 (LAPB)"),
            (ArpHardwareId::DDCMP, "517 (Digital's DDCMP protocol)"),
            (ArpHardwareId::RAWHDLC, "518 (Raw HDLC)"),
            (ArpHardwareId::RAWIP, "519 (Raw IP)"),
            (ArpHardwareId::TUNNEL, "768 (IPIP tunnel)"),
            (ArpHardwareId::TUNNEL6, "769 (IP6IP6 tunnel)"),
            (ArpHardwareId::FRAD, "770 (Frame Relay Access Device)"),
            (ArpHardwareId::SKIP, "771 (SKIP vif)"),
            (ArpHardwareId::LOOPBACK, "772 (Loopback device)"),
            (ArpHardwareId::LOCALTLK, "773 (Localtalk device)"),
            (
                ArpHardwareId::FDDI,
                "774 (Fiber Distributed Data Interface)",
            ),
            (ArpHardwareId::BIF, "775 (AP1000 BIF)"),
            (ArpHardwareId::SIT, "776 (sit0 device - IPv6-in-IPv4)"),
            (ArpHardwareId::IPDDP, "777 (IP over DDP tunneller)"),
            (ArpHardwareId::IPGRE, "778 (GRE over IP)"),
            (ArpHardwareId::PIMREG, "779 (PIMSM register interface)"),
            (
                ArpHardwareId::HIPPI,
                "780 (High Performance Parallel Interface)",
            ),
            (ArpHardwareId::ASH, "781 (Nexus 64Mbps Ash)"),
            (ArpHardwareId::ECONET, "782 (Acorn Econet)"),
            (ArpHardwareId::IRDA, "783 (Linux-IrDA)"),
            (ArpHardwareId::FCPP, "784 (Point to point fibrechannel)"),
            (ArpHardwareId::FCAL, "785 (Fibrechannel arbitrated loop)"),
            (ArpHardwareId::FCPL, "786 (Fibrechannel public loop)"),
            (ArpHardwareId::FCFABRIC, "787 (Fibrechannel fabric)"),
            (ArpHardwareId::IEEE802_TR, "800 (Magic type ident for TR)"),
            (ArpHardwareId::IEEE80211, "801 (IEEE 802.11)"),
            (
                ArpHardwareId::IEEE80211_PRISM,
                "802 (IEEE 802.11 + Prism2 header)",
            ),
            (
                ArpHardwareId::IEEE80211_RADIOTAP,
                "803 (IEEE 802.11 + radiotap header)",
            ),
            (ArpHardwareId::IEEE802154, "804 (IEEE 802.15.4)"),
            (
                ArpHardwareId::IEEE802154_MONITOR,
                "805 (IEEE 802.15.4 network monitor)",
            ),
            (ArpHardwareId::PHONET, "820 (PhoNet media type)"),
            (ArpHardwareId::PHONET_PIPE, "821 (PhoNet pipe header)"),
            (ArpHardwareId::CAIF, "822 (CAIF media type)"),
            (ArpHardwareId::IP6GRE, "823 (GRE over IPv6)"),
            (ArpHardwareId::NETLINK, "824 (Netlink header)"),
            (ArpHardwareId::IPV6LOWPAN, "825 (IPv6 over LoWPAN)"),
            (ArpHardwareId::VSOCKMON, "826 (Vsock monitor header)"),
            (ArpHardwareId::VOID, "0xFFFF (Void type, nothing is known)"),
            (ArpHardwareId::NONE, "0xFFFE (zero header length)"),
            (ArpHardwareId::from(0x1234), "0x1234"),
        ];

        for (ether_type, str_value) in pairs {
            assert_eq!(str_value, &format!("{}", ether_type));
            assert_eq!(str_value, &format!("{:?}", ether_type));
        }
    }

    #[test]
    fn default() {
        let value: ArpHardwareId = Default::default();
        assert_eq!(ArpHardwareId(0), value);
    }

    #[test]
    fn clone_eq() {
        let values = &[
            ArpHardwareId::NETROM,
            ArpHardwareId::ETHERNET,
            ArpHardwareId::EETHER,
            ArpHardwareId::AX25,
            ArpHardwareId::PRONET,
            ArpHardwareId::CHAOS,
            ArpHardwareId::IEEE802,
            ArpHardwareId::ARCNET,
            ArpHardwareId::APPLETLK,
            ArpHardwareId::DLCI,
            ArpHardwareId::ATM,
            ArpHardwareId::METRICOM,
            ArpHardwareId::IEEE1394,
            ArpHardwareId::EUI64,
            ArpHardwareId::INFINIBAND,
            ArpHardwareId::SLIP,
            ArpHardwareId::CSLIP,
            ArpHardwareId::SLIP6,
            ArpHardwareId::CSLIP6,
            ArpHardwareId::RSRVD,
            ArpHardwareId::ADAPT,
            ArpHardwareId::ROSE,
            ArpHardwareId::X25,
            ArpHardwareId::HWX25,
            ArpHardwareId::CAN,
            ArpHardwareId::PPP,
            ArpHardwareId::CISCO_HDLC,
            ArpHardwareId::LAPB,
            ArpHardwareId::DDCMP,
            ArpHardwareId::RAWHDLC,
            ArpHardwareId::RAWIP,
            ArpHardwareId::TUNNEL,
            ArpHardwareId::TUNNEL6,
            ArpHardwareId::FRAD,
            ArpHardwareId::SKIP,
            ArpHardwareId::LOOPBACK,
            ArpHardwareId::LOCALTLK,
            ArpHardwareId::FDDI,
            ArpHardwareId::BIF,
            ArpHardwareId::SIT,
            ArpHardwareId::IPDDP,
            ArpHardwareId::IPGRE,
            ArpHardwareId::PIMREG,
            ArpHardwareId::HIPPI,
            ArpHardwareId::ASH,
            ArpHardwareId::ECONET,
            ArpHardwareId::IRDA,
            ArpHardwareId::FCPP,
            ArpHardwareId::FCAL,
            ArpHardwareId::FCPL,
            ArpHardwareId::FCFABRIC,
            ArpHardwareId::IEEE802_TR,
            ArpHardwareId::IEEE80211,
            ArpHardwareId::IEEE80211_PRISM,
            ArpHardwareId::IEEE80211_RADIOTAP,
            ArpHardwareId::IEEE802154,
            ArpHardwareId::IEEE802154_MONITOR,
            ArpHardwareId::PHONET,
            ArpHardwareId::PHONET_PIPE,
            ArpHardwareId::CAIF,
            ArpHardwareId::IP6GRE,
            ArpHardwareId::NETLINK,
            ArpHardwareId::IPV6LOWPAN,
            ArpHardwareId::VSOCKMON,
            ArpHardwareId::VOID,
            ArpHardwareId::NONE,
        ];

        // clone
        for v in values {
            assert_eq!(v, &v.clone());
        }

        // eq
        for (a_pos, a) in values.iter().enumerate() {
            for (b_pos, b) in values.iter().enumerate() {
                assert_eq!(a_pos == b_pos, a == b);
                assert_eq!(a_pos != b_pos, a != b);
            }
        }
    }
}
