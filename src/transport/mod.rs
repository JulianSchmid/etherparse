pub mod udp;
pub mod tcp;

use super::*;

///The possible headers on the transport layer
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportHeader {
    Udp(udp::UdpHeader),
    Tcp(tcp::TcpHeader)
}

impl TransportHeader {

    ///Returns Result::Some containing the udp header if self has the value Udp. 
    ///Otherwise None is returned.
    pub fn udp(self) -> Option<udp::UdpHeader> {
        use TransportHeader::*;
        match self {
            Udp(value) => Some(value),
            Tcp(_) => None
        }
    }

    ///Returns Result::Some containing the udp header if self has the value Udp. 
    ///Otherwise None is returned.
    pub fn mut_udp<'a>(&'a mut self) -> Option<&'a mut udp::UdpHeader> {
        use TransportHeader::*;
        match self {
            Udp(ref mut value) => Some(value),
            Tcp(_) => None
        }
    }

    ///Returns Result::Some containing the tcp header if self has the value Tcp. 
    ///Otherwise None is returned.
    pub fn tcp(self) -> Option<tcp::TcpHeader> {
        use TransportHeader::*;
        match self {
            Udp(_) => None,
            Tcp(value) => Some(value)
        }
    }

    ///Returns Result::Some containing a mutable refernce to the tcp header if self has the value Tcp. 
    ///Otherwise None is returned.
    pub fn mut_tcp<'a>(&'a mut self) -> Option<&'a mut tcp::TcpHeader> {
        use TransportHeader::*;
        match self {
            Udp(_) => None,
            Tcp(ref mut value) => Some(value)
        }
    }

    ///Returns the size of the transport header (in case of UDP fixed, 
    ///in case of TCP cotanining the options).dd
    pub fn header_len(&self) -> usize {
        use TransportHeader::*;
        match self {
            Udp(_) => udp::UdpHeader::SERIALIZED_SIZE,
            Tcp(value) => value.header_len() as usize
        }
    }

    ///Calculates the checksum for the transport header & sets it in the header for
    ///an ipv4 header.
    pub fn update_checksum_ipv4(&mut self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<(), ValueError> {
        use TransportHeader::*;
        match self {
            Udp(header) => {
                header.checksum = match header.calc_checksum_ipv4(ip_header, payload) {
                    Ok(value) => value,
                    Err(err) => return Err(err)
                };
                Ok(())
            },
            Tcp(header) => {
                header.checksum = match header.calc_checksum_ipv4(ip_header, payload) {
                    Ok(value) => value,
                    Err(err) => return Err(err)
                };
                Ok(())
            }
        }
    }

    ///Calculates the checksum for the transport header & sets it in the header for
    ///an ipv6 header.
    pub fn update_checksum_ipv6(&mut self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<(), ValueError> {
        use TransportHeader::*;
        match self {
            Udp(header) => {
                header.checksum = match header.calc_checksum_ipv6(ip_header, payload) {
                    Ok(value) => value,
                    Err(err) => return Err(err)
                };
                Ok(())
            },
            Tcp(header) => {
                header.checksum = match header.calc_checksum_ipv6(ip_header, payload) {
                    Ok(value) => value,
                    Err(err) => return Err(err)
                };
                Ok(())
            }
        }
    }

    ///Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use TransportHeader::*;
        match self {
            Udp(value) => value.write(writer),
            Tcp(value) => match value.write(writer) {
                Ok(value) => Ok(value),
                Err(err) => Err(WriteError::IoError(err))
            }
        }
    }
}

#[cfg(test)]
mod whitebox_tests {
    #[test]
    pub fn dummy() {
        assert_eq!(true, true);
    }
}