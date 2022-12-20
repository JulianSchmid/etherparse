use crate::*;
use std::fmt::{Debug, Formatter};

/// IPv4 header without options.
#[derive(Clone)]
pub struct Ipv4Header {
    pub differentiated_services_code_point: u8,
    pub explicit_congestion_notification: u8,
    /// Length of the payload of the ipv4 packet in bytes (does not contain the options).
    ///
    /// This field does not directly exist in an ipv4 header but instead is decoded from
    /// & encoded to the total_size field together with the options length (using the ihl).
    ///
    /// Headers where the total length is smaller then then the minimum header size itself
    /// are not representable in this struct.
    pub payload_len: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragments_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: [u8;4],
    pub destination: [u8;4],
    /// Length of the options in the options_buffer in bytes.
    options_len: u8,
    options_buffer: [u8;40]
}

impl SerializedSize for Ipv4Header {
    /// Size of the header itself (without options) in bytes.
    const SERIALIZED_SIZE:usize = 20;
}

const IPV4_MAX_OPTIONS_LENGTH: usize = 10*4;

impl Ipv4Header {
    ///Constructs an Ipv4Header with standard values for non specified values.
    pub fn new(payload_len: u16, time_to_live: u8, protocol: u8, source: [u8;4], destination: [u8;4]) -> Ipv4Header {
        Ipv4Header {
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            payload_len,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live,
            protocol,
            header_checksum: 0,
            source,
            destination,
            options_len: 0,
            options_buffer: [0;40]
        }
    }

    ///Length of the header in 4 bytes (often also called IHL - Internet Header Lenght). 
    ///
    ///The minimum allowed length of a header is 5 (= 20 bytes) and the maximum length is 15 (= 60 bytes).
    pub fn ihl(&self) -> u8 {
        (self.options_len/4) + 5
    }

    ///Returns a slice to the options part of the header (empty if no options are present).
    pub fn options(&self) -> &[u8] {
        &self.options_buffer[..usize::from(self.options_len)]
    }

    ///Length of the header (includes options) in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        Ipv4Header::SERIALIZED_SIZE + usize::from(self.options_len)
    }

    ///Returns the total length of the header + payload in bytes.
    pub fn total_len(&self) -> u16 {
        self.payload_len + (Ipv4Header::SERIALIZED_SIZE as u16) + u16::from(self.options_len)
    }

    ///Sets the payload length if the value is not too big. Otherwise an error is returned.
    pub fn set_payload_len(&mut self, value: usize) -> Result<(), ValueError> {
        if usize::from(self.max_payload_len()) < value {
            use crate::ValueError::*;
            Err(Ipv4PayloadLengthTooLarge(value))
        } else {
            self.payload_len = value as u16;
            Ok(())
        }
    }

    ///Returns the maximum payload size based on the current options size.
    pub fn max_payload_len(&self) -> u16 {
        std::u16::MAX - u16::from(self.options_len) - (Ipv4Header::SERIALIZED_SIZE as u16)
    }

    ///Sets the options & header_length based on the provided length.
    ///The length of the given slice must be a multiple of 4 and maximum 40 bytes.
    ///If the length is not fullfilling these constraints, no data is set and
    ///an error is returned.
    pub fn set_options(&mut self, data: &[u8]) -> Result<(), ValueError> {
        use crate::ValueError::*;

        //check that the options length is within bounds
        if (IPV4_MAX_OPTIONS_LENGTH < data.len()) ||
           (0 != data.len() % 4)
        {
            Err(Ipv4OptionsLengthBad(data.len()))
        } else {
            //copy the data to the buffer
            self.options_buffer[..data.len()].copy_from_slice(data);

            //set the header length
            self.options_len = data.len() as u8;
            Ok(())
        }
    }

    /// Renamed to `Ipv4Header::from_slice`
    #[deprecated(
        since = "0.10.1",
        note = "Renamed to `Ipv4Header::from_slice`"
    )]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ipv4Header, &[u8]), ReadError> {
        Ipv4Header::from_slice(slice)
    }

    /// Read an Ipv4Header from a slice and return the header & unused parts of the slice.
    pub fn from_slice(slice: &[u8]) -> Result<(Ipv4Header, &[u8]), ReadError> {
        let header = Ipv4HeaderSlice::from_slice(slice)?.to_header();
        let rest = &slice[header.header_len()..];
        Ok((
            header,
            rest
        ))
    }

    /// Decode all the header fields and copy the results to a Ipv4Header struct
    pub fn from_ipv4_slice(slice: &Ipv4HeaderSlice) -> Ipv4Header {
        let options = slice.options();
        Ipv4Header {
            differentiated_services_code_point: slice.dcp(),
            explicit_congestion_notification: slice.ecn(),
            payload_len: slice.payload_len(),
            identification: slice.identification(),
            dont_fragment: slice.dont_fragment(),
            more_fragments: slice.more_fragments(),
            fragments_offset: slice.fragments_offset(),
            time_to_live: slice.ttl(),
            protocol: slice.protocol(),
            header_checksum: slice.header_checksum(),
            source: slice.source(),
            destination: slice.destination(),
            options_len: options.len() as u8,
            options_buffer: {
                let mut result: [u8;40] = [0;40];
                result[..options.len()].copy_from_slice(options);
                result
            }
        }
    }

    /// Reads an IPv4 header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ipv4Header, ReadError> {
        let mut first_byte : [u8;1] = [0;1];
        reader.read_exact(&mut first_byte)?;

        let version = first_byte[0] >> 4;
        if 4 != version {
            return Err(ReadError::Ipv4UnexpectedVersion(version));
        }
        Ipv4Header::read_without_version(reader, first_byte[0])
    }

    /// Reads an IPv4 header assuming the version & ihl field have already been read.
    pub fn read_without_version<T: io::Read + io::Seek + Sized>(reader: &mut T, first_byte: u8) -> Result<Ipv4Header, ReadError> {
        
        let mut header_raw : [u8;20] = [0;20];
        header_raw[0] = first_byte;
        reader.read_exact(&mut header_raw[1..])?;

        let ihl = header_raw[0] & 0xf;
        if ihl < 5 {
            use crate::ReadError::*;
            return Err(Ipv4HeaderLengthBad(ihl));
        }

        let (dscp, ecn) = {
            let value = header_raw[1];
            (value >> 2, value & 0x3)
        };
        let header_length = u16::from(ihl)*4;
        let total_length = u16::from_be_bytes([header_raw[2], header_raw[3]]);
        if total_length < header_length {
            use crate::ReadError::*;
            return Err(Ipv4TotalLengthTooSmall(total_length));
        }
        let identification = u16::from_be_bytes([header_raw[4], header_raw[5]]);
        let (dont_fragment, more_fragments, fragments_offset) = (
            0 != (header_raw[6] & 0b0100_0000),
            0 != (header_raw[6] & 0b0010_0000),
            u16::from_be_bytes(
                [header_raw[6] & 0b0001_1111, header_raw[7]]
            )
        );
        Ok(Ipv4Header{
            differentiated_services_code_point: dscp,
            explicit_congestion_notification: ecn,
            payload_len: total_length - header_length,
            identification,
            dont_fragment,
            more_fragments,
            fragments_offset,
            time_to_live: header_raw[8],
            protocol: header_raw[9],
            header_checksum: u16::from_be_bytes([header_raw[10], header_raw[11]]),
            source: [header_raw[12], header_raw[13], header_raw[14], header_raw[15]],
            destination: [header_raw[16], header_raw[17], header_raw[18], header_raw[19]],
            options_len: (ihl - 5)*4,
            options_buffer: {
                let mut values: [u8;40] = [0;40];
                
                let options_len = usize::from(ihl - 5)*4;
                if options_len > 0 {
                    reader.read_exact(&mut values[..options_len])?;
                }
                values
            },
        })
    }

    /// Checks if the values in this header are valid values for an ipv4 header.
    ///
    /// Specifically it will be checked, that:
    /// * payload_len + options_len is not too big to be encoded in the total_size header field
    /// * differentiated_services_code_point is not greater then 0x3f
    /// * explicit_congestion_notification is not greater then 0x3
    /// * fragments_offset is not greater then 0x1fff
    pub fn check_ranges(&self) -> Result<(), ValueError> {
        use crate::ErrorField::*;
        
        //check ranges
        max_check_u8(self.differentiated_services_code_point, 0x3f, Ipv4Dscp)?;
        max_check_u8(self.explicit_congestion_notification, 0x3, Ipv4Ecn)?;
        max_check_u16(self.fragments_offset, 0x1fff, Ipv4FragmentsOffset)?;
        max_check_u16(self.payload_len, self.max_payload_len(), Ipv4PayloadLength)?;

        Ok(())
    }

    /// Writes a given IPv4 header to the current position (this method automatically calculates the header length and checksum).
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        //check ranges
        self.check_ranges()?;

        //write with recalculations
        self.write_ipv4_header_internal(writer, self.calc_header_checksum_unchecked())
    }

    /// Writes a given IPv4 header to the current position (this method just writes the specified checksum and does note compute it).
    pub fn write_raw<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        //check ranges
        self.check_ranges()?;

        //write
        self.write_ipv4_header_internal(writer, self.header_checksum)
    }

    /// Write the given header with the  checksum and header length specified in the seperate arguments
    fn write_ipv4_header_internal<T: io::Write>(&self, write: &mut T, header_checksum: u16) -> Result<(), WriteError> {
        let total_len_be = self.total_len().to_be_bytes();
        let id_be = self.identification.to_be_bytes();
        let frag_and_flags = {
            let frag_be: [u8;2] = self.fragments_offset.to_be_bytes();
            let flags = {
                let mut result = 0;
                if self.dont_fragment {
                    result |= 64;
                }
                if self.more_fragments {
                    result |= 32;
                }
                result
            };
            [
                flags | (frag_be[0] & 0x1f),
                frag_be[1],
            ]
        };
        let header_checksum_be = header_checksum.to_be_bytes();

        let header_raw = [
            (4 << 4) | self.ihl(),
            (self.differentiated_services_code_point << 2) | self.explicit_congestion_notification,
            total_len_be[0],
            total_len_be[1],

            id_be[0],
            id_be[1],
            frag_and_flags[0],
            frag_and_flags[1],

            self.time_to_live,
            self.protocol,
            header_checksum_be[0],
            header_checksum_be[1],

            self.source[0],
            self.source[1],
            self.source[2],
            self.source[3],

            self.destination[0],
            self.destination[1],
            self.destination[2],
            self.destination[3],
        ];
        write.write_all(&header_raw)?;

        //options
        write.write_all(self.options())?;

        //done
        Ok(())
    }

    /// Calculate header checksum of the current ipv4 header.
    pub fn calc_header_checksum(&self) -> Result<u16, ValueError> {

        //check ranges
        self.check_ranges()?;

        //calculate the checksum
        Ok(self.calc_header_checksum_unchecked())
    }

    /// Calculate the header checksum under the assumtion that all value ranges in the header are correct
    fn calc_header_checksum_unchecked(&self) -> u16 {
        checksum::Sum16BitWords::new()
        .add_2bytes(
            [
                (4 << 4) | self.ihl(),
                (self.differentiated_services_code_point << 2) | self.explicit_congestion_notification 
            ]
        )
        .add_2bytes(self.total_len().to_be_bytes())
        .add_2bytes(self.identification.to_be_bytes())
        .add_2bytes(
            {
                let frag_off_be = self.fragments_offset.to_be_bytes();
                let flags = {
                    let mut result = 0;
                    if self.dont_fragment {
                        result |= 64;
                    }
                    if self.more_fragments {
                        result |= 32;
                    }
                    result
                };
                [
                    flags | (frag_off_be[0] & 0x1f),
                    frag_off_be[1]
                ]
            }
        )
        .add_2bytes([self.time_to_live, self.protocol])
        .add_4bytes(self.source)
        .add_4bytes(self.destination)
        .add_slice(self.options())
        .ones_complement()
        .to_be()
    }

    /// Returns true if the payload is fragmented.
    ///
    /// Either data is missing (more_fragments set) or there is
    /// an fragment offset.
    #[inline]
    pub fn is_fragmenting_payload(&self) -> bool {
        self.more_fragments ||
        (0 != self.fragments_offset)
    }
}

//NOTE: I would have prefered to NOT write my own Default, Debug & PartialEq implementation but there are no
//      default implementations availible for [u8;40] and the alternative of using [u32;10] would lead
//      to unsafe casting. Writing impl Debug for [u8;40] in a crate is also illegal as it could lead 
//      to an implementation collision between crates.
//      So the only option left to me was to write an implementation myself and deal with the added complexity
//      and potential added error source.

impl Default for Ipv4Header {
    fn default() -> Ipv4Header {
        Ipv4Header {
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            payload_len: 0,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live: 0,
            protocol: 0,
            header_checksum: 0,
            source: [0;4],
            destination: [0;4],
            options_len: 0,
            options_buffer: [0;40]
        }
    }
}

impl Debug for Ipv4Header {
    fn fmt(&self, fotmatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(fotmatter, "Ipv4Header {{ ihl: {}, differentiated_services_code_point: {}, explicit_congestion_notification: {}, payload_len: {}, identification: {}, dont_fragment: {}, more_fragments: {}, fragments_offset: {}, time_to_live: {}, protocol: {}, header_checksum: {}, source: {:?}, destination: {:?}, options: {:?} }}", 
            self.ihl(),
            self.differentiated_services_code_point,
            self.explicit_congestion_notification,
            self.payload_len,
            self.identification,
            self.dont_fragment,
            self.more_fragments,
            self.fragments_offset,
            self.time_to_live,
            self.protocol,
            self.header_checksum,
            self.source,
            self.destination,
            self.options())
    }
}

impl std::cmp::PartialEq for Ipv4Header {
    fn eq(&self, other: &Ipv4Header) -> bool {
        self.differentiated_services_code_point == other.differentiated_services_code_point &&
        self.explicit_congestion_notification == other.explicit_congestion_notification &&
        self.payload_len == other.payload_len &&
        self.identification == other.identification &&
        self.dont_fragment == other.dont_fragment &&
        self.more_fragments == other.more_fragments &&
        self.fragments_offset == other.fragments_offset &&
        self.time_to_live == other.time_to_live &&
        self.protocol == other.protocol &&
        self.header_checksum == other.header_checksum &&
        self.source == other.source &&
        self.destination == other.destination &&
        self.options_len == other.options_len &&
        self.options() == other.options()
    }
}

impl std::cmp::Eq for Ipv4Header {}
