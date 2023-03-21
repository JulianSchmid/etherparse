use super::super::*;

use std::slice::from_raw_parts;

///Udp header according to rfc768.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UdpHeader {
    ///Source port of the packet (optional).
    pub source_port: u16,
    ///Destination port of the packet.
    pub destination_port: u16,
    ///Length of the packet (includes the udp header length of 8 bytes).
    pub length: u16,
    ///The checksum of the packet. The checksum is calculated from a pseudo header, the udp header and the payload. The pseudo header is composed of source and destination address, protocol number 
    pub checksum: u16
}

impl UdpHeader {

    /// Returns an udp header for the given parameters
    pub fn without_ipv4_checksum(source_port: u16, destination_port: u16, payload_length: usize) -> Result<UdpHeader, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload_length {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload_length));
        }

        Ok(UdpHeader{
            source_port,
            destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload_length) as u16, //payload plus udp header
            checksum: 0
        })
    }

    /// Calculate an udp header given an ipv4 header and the payload
    pub fn with_ipv4_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv4Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {

        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        let mut result = UdpHeader{
            source_port,
            destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16, //payload plus udp header
            checksum: 0
        };
        result.checksum = result.calc_checksum_ipv4_internal(ip_header.source, ip_header.destination, payload);
        Ok(result)
    }

    /// Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, payload)
    }

    /// Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4_raw(&self, source: [u8;4], destination: [u8;4], payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv4_internal(source, destination, payload))
    }
    
    /// Calculates the upd header checksum based on a ipv4 header.
    fn calc_checksum_ipv4_internal(&self, source: [u8;4], destination: [u8;4], payload: &[u8]) -> u16 {

        self.calc_checksum_post_ip(
            //pseudo header
            checksum::Sum16BitWords::new()
            .add_4bytes(source)
            .add_4bytes(destination)
            .add_2bytes([0, ip_number::UDP])
            .add_2bytes(self.length.to_be_bytes()), 
            payload
        )
    }

    /// Calculate an udp header given an ipv6 header and the payload
    pub fn with_ipv6_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv6Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {

        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH <= payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        let mut result = UdpHeader{
            source_port,
            destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16, //payload plus udp header
            checksum: 0
        };
        result.checksum = result.calc_checksum_ipv6_internal(ip_header.source, ip_header.destination, payload);
        Ok(result)
    }

    /// Calculates the checksum of the current udp header given an ipv6 header and the payload.
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, payload)
    }

    /// Calculates the checksum of the current udp header given an ipv6 source & destination address plus the payload.
    pub fn calc_checksum_ipv6_raw(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u32::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv6_internal(source, destination, payload))
    }

    fn calc_checksum_ipv6_internal(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> u16 {
        self.calc_checksum_post_ip(
            //pseudo header
            checksum::Sum16BitWords::new()
            .add_16bytes(source)
            .add_16bytes(destination)
            .add_2bytes([0, ip_number::UDP])
            .add_2bytes(self.length.to_be_bytes()),
            payload
        )
    }

    /// This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: checksum::Sum16BitWords, payload: &[u8]) -> u16 {
        ip_pseudo_header_sum
        .add_2bytes(self.source_port.to_be_bytes())
        .add_2bytes(self.destination_port.to_be_bytes())
        .add_2bytes(self.length.to_be_bytes())
        .add_slice(payload)
        .to_ones_complement_with_no_zero()
        .to_be()
    }

    /// Reads a udp header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[deprecated(
        since = "0.10.1",
        note = "Use UdpHeader::from_slice instead."
    )]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(UdpHeader, &[u8]), ReadError> {
        UdpHeader::from_slice(slice)
    }

    /// Reads a udp header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(UdpHeader, &[u8]), ReadError> {
        Ok((
            UdpHeaderSlice::from_slice(slice)?.to_header(),
            &slice[UdpHeader::SERIALIZED_SIZE..]
        ))
    }

    /// Read an UdpHeader from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8;8]) -> UdpHeader {
        UdpHeader{
            source_port: u16::from_be_bytes(
                [
                    bytes[0],
                    bytes[1],
                ]
            ),
            destination_port: u16::from_be_bytes(
                [
                    bytes[2],
                    bytes[3],
                ]
            ),
            length: u16::from_be_bytes(
                [
                    bytes[4],
                    bytes[5],
                ]
            ),
            checksum: u16::from_be_bytes(
                [
                    bytes[6],
                    bytes[7],
                ]
            ),
        }
    }

    /// Tries to read an udp header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<UdpHeader, io::Error> {
        let bytes = {
            let mut bytes : [u8;8] = [0;8];
            reader.read_exact(&mut bytes)?;
            bytes
        };
        Ok(UdpHeader::from_bytes(bytes))
    }

    /// Write the udp header without recalculating the checksum or length.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Length of the serialized header in bytes.
    ///
    /// The function always returns the constant UdpHeader::SERIALIZED_SIZE
    /// and exists to keep the methods consistent with other headers.
    #[inline]
    pub fn header_len(&self) -> usize {
        UdpHeader::SERIALIZED_SIZE
    }

    /// Returns the serialized form of the header as a statically
    /// sized byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8;8] {
        let source_port_be = self.source_port.to_be_bytes();
        let destination_port_be = self.destination_port.to_be_bytes();
        let length_be = self.length.to_be_bytes();
        let checksum = self.checksum.to_be_bytes();
        [
            source_port_be[0],
            source_port_be[1],
            destination_port_be[0],
            destination_port_be[1],
            length_be[0],
            length_be[1],
            checksum[0],
            checksum[1],
        ]
    }
}

impl SerializedSize for UdpHeader {
    ///Size of the header itself
    const SERIALIZED_SIZE: usize = 8;
}

///A slice containing an udp header of a network package. Struct allows the selective read of fields in the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> UdpHeaderSlice<'a> {

    /// Creates a slice containing an udp header.
    #[inline]
    pub fn from_slice(slice: &'a[u8]) -> Result<UdpHeaderSlice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < UdpHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(UdpHeader::SERIALIZED_SIZE));
        }

        //done
        Ok(UdpHeaderSlice{
            // SAFETY:
            // Safe as slice length is checked to be at least
            // UdpHeader::SERIALIZED_SIZE (8) before this.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    UdpHeader::SERIALIZED_SIZE
                )
            }
        })
    }

    /// Returns the slice containing the udp header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Reads the "udp source port" from the slice.
    #[inline]
    pub fn source_port(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr())
        }
    }

    /// Reads the "udp destination port" from the slice.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(2))
        }
    }

    /// Reads the "length" from the slice.
    #[inline]
    pub fn length(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(4))
        }
    }

    /// Reads the "checksum" from the slice.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(6))
        }
    }

    /// Decode all the fields and copy the results to a UdpHeader struct
    #[inline]
    pub fn to_header(&self) -> UdpHeader {
        UdpHeader {
            source_port: self.source_port(),
            destination_port: self.destination_port(),
            length: self.length(),
            checksum: self.checksum()
        }
    }

    /// Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4HeaderSlice, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source(), ip_header.destination(), payload)
    }

    /// Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4_raw(&self, source: [u8;4], destination: [u8;4], payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv4_internal(source, destination, payload))
    }

    /// Calculates the upd header checksum based on a ipv4 header.
    fn calc_checksum_ipv4_internal(&self, source: [u8;4], destination: [u8;4], payload: &[u8]) -> u16 {

        self.calc_checksum_post_ip(
            //pseudo header
            checksum::Sum16BitWords::new()
                .add_4bytes(source)
                .add_4bytes(destination)
                .add_2bytes([0, ip_number::UDP])
                .add_2bytes(self.length().to_be_bytes()),
            payload
        )
    }

    /// Calculates the checksum of the current udp header given an ipv6 header and the payload.
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6HeaderSlice, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source(), ip_header.destination(), payload)
    }

    /// Calculates the checksum of the current udp header given an ipv6 source & destination address plus the payload.
    pub fn calc_checksum_ipv6_raw(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u32::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv6_internal(source, destination, payload))
    }

    fn calc_checksum_ipv6_internal(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> u16 {
        self.calc_checksum_post_ip(
            //pseudo header
            checksum::Sum16BitWords::new()
                .add_16bytes(source)
                .add_16bytes(destination)
                .add_2bytes([0, ip_number::UDP])
                .add_2bytes(self.length().to_be_bytes()),
            payload
        )
    }

    /// This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: checksum::Sum16BitWords, payload: &[u8]) -> u16 {
        ip_pseudo_header_sum
            .add_2bytes(self.source_port().to_be_bytes())
            .add_2bytes(self.destination_port().to_be_bytes())
            .add_2bytes(self.length().to_be_bytes())
            .add_slice(payload)
            .to_ones_complement_with_no_zero()
            .to_be()
    }
}
