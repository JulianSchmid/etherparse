use super::*;

mod header {
    use super::*;

    #[test]
    fn debug() {
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