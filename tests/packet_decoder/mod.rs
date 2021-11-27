use super::*;

mod header {
    use super::*;

    #[test]
    fn debug() {
        /*pub link: Option<Ethernet2Header>,
        pub vlan: Option<VlanHeader>,
        pub ip: Option<IpHeader>,
        pub transport: Option<TransportHeader>,
        /// Rest of the packet that could not be decoded as a header (usually the payload).
        pub payload: &'a [u8]*/
        let header = PacketHeaders{
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[]
        };
        assert_eq!(
            &format!("{:?}", header),
            &format!(
                "PacketHeaders {{ link: {:?}, vlan: {:?}, ip: {:?}, transport: {:?}, payload: {:?} }}",
                header.link,
                header.vlan,
                header.ip,
                header.transport,
                header.payload
            )
        );
    }

    #[test]
    fn clone_eq() {
        let header = PacketHeaders{
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[]
        };
        assert_eq!(header.clone(), header);
    }

}