use super::*;

#[test]
fn from_ip_errors() {
    use crate::ReadError::*;

    //slice length error
    assert_matches!(
        SlicedPacket::from_ip(&[]),
        Err(UnexpectedEndOfSlice(1))
    );

    //bad protocol number
    for i in 0u8..std::u8::MAX {
        if i >> 4 != 4  && 
           i >> 4 != 6
        {
            assert_matches!(
                SlicedPacket::from_ip(&[i]),
                Err(IpUnsupportedVersion(_))
            );
        }
    }
}