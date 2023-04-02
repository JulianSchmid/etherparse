use arrayvec::ArrayVec;

use crate::*;
use core::fmt::{Debug, Formatter};

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
    pub source: [u8; 4],
    pub destination: [u8; 4],
    /// Length of the options in the options_buffer in bytes.
    pub(crate) options_len: u8,
    pub(crate) options_buffer: [u8; 40],
}

const IPV4_MAX_OPTIONS_LENGTH: usize = 10 * 4;

impl Ipv4Header {
    /// Minimum length of an IPv4 header in bytes/octets.
    pub const MIN_LEN: usize = 20;

    /// Maximum length of an IPv4 header in bytes/octets.
    ///
    /// This number is calculated by taking the maximum value
    /// that the "internet header length" field supports (0xf,
    /// as the field is only 4 bits long) and multiplying it
    /// with 4 as the "internet header length" specifies how
    /// many 4 bytes words are present in the header.
    pub const MAX_LEN: usize = 0b1111 * 4;

    /// Deprecated use [`Ipv4Header::MIN_LEN`] instead.
    #[deprecated(since = "0.14.0", note = "Use `Ipv4Header::MIN_LEN` instead")]
    pub const SERIALIZED_SIZE: usize = Ipv4Header::MIN_LEN;

    /// Constructs an Ipv4Header with standard values for non specified values.
    pub fn new(
        payload_len: u16,
        time_to_live: u8,
        protocol: u8,
        source: [u8; 4],
        destination: [u8; 4],
    ) -> Ipv4Header {
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
            options_buffer: [0; 40],
        }
    }

    /// Length of the header in 4 bytes (often also called IHL - Internet Header Lenght).
    ///
    /// The minimum allowed length of a header is 5 (= 20 bytes) and the maximum length is 15 (= 60 bytes).
    pub fn ihl(&self) -> u8 {
        (self.options_len / 4) + 5
    }

    /// Length of the header (includes options) in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        Ipv4Header::MIN_LEN + usize::from(self.options_len)
    }

    /// Returns the total length of the header + payload in bytes.
    pub fn total_len(&self) -> u16 {
        self.payload_len + (Ipv4Header::MIN_LEN as u16) + u16::from(self.options_len)
    }

    /// Sets the payload length if the value is not too big. Otherwise an error is returned.
    pub fn set_payload_len(&mut self, value: usize) -> Result<(), ValueError> {
        if usize::from(self.max_payload_len()) < value {
            use crate::ValueError::*;
            Err(Ipv4PayloadLengthTooLarge(value))
        } else {
            self.payload_len = value as u16;
            Ok(())
        }
    }

    /// Returns the maximum payload size based on the current options size.
    pub fn max_payload_len(&self) -> u16 {
        core::u16::MAX - u16::from(self.options_len) - (Ipv4Header::MIN_LEN as u16)
    }

    /// Returns a slice to the options part of the header (empty if no options are present).
    pub fn options(&self) -> &[u8] {
        &self.options_buffer[..usize::from(self.options_len)]
    }

    /// Sets the options & header_length based on the provided length.
    /// The length of the given slice must be a multiple of 4 and maximum 40 bytes.
    /// If the length is not fullfilling these constraints, no data is set and
    /// an error is returned.
    pub fn set_options(&mut self, data: &[u8]) -> Result<(), ValueError> {
        use crate::ValueError::*;

        //check that the options length is within bounds
        if (IPV4_MAX_OPTIONS_LENGTH < data.len()) || (0 != data.len() % 4) {
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
    #[deprecated(since = "0.10.1", note = "Renamed to `Ipv4Header::from_slice`")]
    #[inline]
    pub fn read_from_slice(
        slice: &[u8],
    ) -> Result<(Ipv4Header, &[u8]), err::ipv4::HeaderSliceError> {
        Ipv4Header::from_slice(slice)
    }

    /// Read an Ipv4Header from a slice and return the header & unused parts of the slice.
    pub fn from_slice(slice: &[u8]) -> Result<(Ipv4Header, &[u8]), err::ipv4::HeaderSliceError> {
        let header = Ipv4HeaderSlice::from_slice(slice)?.to_header();
        let rest = &slice[header.header_len()..];
        Ok((header, rest))
    }

    /// Reads an IPv4 header from the current position.
    #[cfg(feature = "std")]
    pub fn read<T: std::io::Read + std::io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<Ipv4Header, err::ipv4::HeaderReadError> {
        use err::ipv4::HeaderReadError::*;

        let mut first_byte: [u8; 1] = [0; 1];
        reader.read_exact(&mut first_byte).map_err(|err| Io(err))?;

        let version_number = first_byte[0] >> 4;
        if 4 != version_number {
            use err::ipv4::HeaderError::UnexpectedVersion;
            return Err(Content(UnexpectedVersion { version_number }));
        }
        Ipv4Header::read_without_version(reader, first_byte[0])
    }

    /// Reads an IPv4 header assuming the version & ihl field have already been read.
    #[cfg(feature = "std")]
    pub fn read_without_version<T: std::io::Read + std::io::Seek + Sized>(
        reader: &mut T,
        first_byte: u8,
    ) -> Result<Ipv4Header, err::ipv4::HeaderReadError> {
        use err::ipv4::HeaderError::*;
        use err::ipv4::HeaderReadError::*;

        // read the basic ipv4 header (the header options can be
        // read only after the internet header length was read)
        let mut header_raw = [0u8; 20];
        header_raw[0] = first_byte;
        reader
            .read_exact(&mut header_raw[1..])
            .map_err(|err| Io(err))?;

        let ihl = header_raw[0] & 0xf;

        // validate that the internet header length is big enough to
        // contain a basic IPv4 header without options.
        if ihl < 5 {
            return Err(Content(HeaderLengthSmallerThanHeader { ihl }));
        }

        let (dscp, ecn) = {
            let value = header_raw[1];
            (value >> 2, value & 0x3)
        };
        let header_length = u16::from(ihl) * 4;
        let total_length = u16::from_be_bytes([header_raw[2], header_raw[3]]);

        // validate the total length
        if total_length < header_length {
            return Err(Content(TotalLengthSmallerThanHeader {
                total_length,
                min_expected_length: header_length,
            }));
        }
        let identification = u16::from_be_bytes([header_raw[4], header_raw[5]]);
        let (dont_fragment, more_fragments, fragments_offset) = (
            0 != (header_raw[6] & 0b0100_0000),
            0 != (header_raw[6] & 0b0010_0000),
            u16::from_be_bytes([header_raw[6] & 0b0001_1111, header_raw[7]]),
        );
        Ok(Ipv4Header {
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
            source: [
                header_raw[12],
                header_raw[13],
                header_raw[14],
                header_raw[15],
            ],
            destination: [
                header_raw[16],
                header_raw[17],
                header_raw[18],
                header_raw[19],
            ],
            options_len: (ihl - 5) * 4,
            options_buffer: {
                let mut values = [0u8; 40];

                let options_len = usize::from(ihl - 5) * 4;
                if options_len > 0 {
                    reader
                        .read_exact(&mut values[..options_len])
                        .map_err(|err| Io(err))?;
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
    #[cfg(feature = "std")]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        //check ranges
        self.check_ranges()?;

        //write with recalculations
        self.write_ipv4_header_internal(writer, self.calc_header_checksum_unchecked())
    }

    /// Writes a given IPv4 header to the current position (this method just writes the specified checksum and does note compute it).
    #[cfg(feature = "std")]
    pub fn write_raw<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        //check ranges
        self.check_ranges()?;

        //write
        self.write_ipv4_header_internal(writer, self.header_checksum)
    }

    /// Returns the serialized header (note that this method does NOT
    /// update & calculate the checksum).
    pub fn to_bytes(&self) -> Result<ArrayVec<u8, { Ipv4Header::MAX_LEN }>, ValueError> {
        //check ranges
        self.check_ranges()?;

        // prep the values for copy
        let total_len_be = self.total_len().to_be_bytes();
        let id_be = self.identification.to_be_bytes();
        let frag_and_flags = {
            let frag_be: [u8; 2] = self.fragments_offset.to_be_bytes();
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
            [flags | (frag_be[0] & 0x1f), frag_be[1]]
        };
        let header_checksum_be = self.header_checksum.to_be_bytes();

        #[rustfmt::skip]
        let mut header_raw: ArrayVec<u8, { Ipv4Header::MAX_LEN } > = [
            (4 << 4) | self.ihl(),
            (self.differentiated_services_code_point << 2) | self.explicit_congestion_notification,
            total_len_be[0],
            total_len_be[1],

            id_be[0], id_be[1], frag_and_flags[0], frag_and_flags[1],

            self.time_to_live, self.protocol, header_checksum_be[0], header_checksum_be[1],
            self.source[0], self.source[1], self.source[2], self.source[3],

            self.destination[0], self.destination[1], self.destination[2], self.destination[3],
            self.options_buffer[0], self.options_buffer[1], self.options_buffer[2], self.options_buffer[3],

            self.options_buffer[4], self.options_buffer[5], self.options_buffer[6], self.options_buffer[7],
            self.options_buffer[8], self.options_buffer[9], self.options_buffer[10], self.options_buffer[11],

            self.options_buffer[12], self.options_buffer[13], self.options_buffer[14], self.options_buffer[15],
            self.options_buffer[16], self.options_buffer[17], self.options_buffer[18], self.options_buffer[19],

            self.options_buffer[20], self.options_buffer[21], self.options_buffer[22], self.options_buffer[23],
            self.options_buffer[24], self.options_buffer[25], self.options_buffer[26], self.options_buffer[27],

            self.options_buffer[28], self.options_buffer[29], self.options_buffer[30], self.options_buffer[31],
            self.options_buffer[32], self.options_buffer[33], self.options_buffer[34], self.options_buffer[35],

            self.options_buffer[36], self.options_buffer[37], self.options_buffer[38], self.options_buffer[39],
        ].into();

        // SAFETY: Safe as header_len() can never exceed the maximum length of an
        // IPv4 header which is the upper limit of the array vec.
        unsafe {
            header_raw.set_len(self.header_len());
        }

        Ok(header_raw)
    }

    /// Write the given header with the  checksum and header length specified in the seperate arguments
    #[cfg(feature = "std")]
    fn write_ipv4_header_internal<T: std::io::Write>(
        &self,
        write: &mut T,
        header_checksum: u16,
    ) -> Result<(), WriteError> {
        let total_len_be = self.total_len().to_be_bytes();
        let id_be = self.identification.to_be_bytes();
        let frag_and_flags = {
            let frag_be: [u8; 2] = self.fragments_offset.to_be_bytes();
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
            [flags | (frag_be[0] & 0x1f), frag_be[1]]
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
            .add_2bytes([
                (4 << 4) | self.ihl(),
                (self.differentiated_services_code_point << 2)
                    | self.explicit_congestion_notification,
            ])
            .add_2bytes(self.total_len().to_be_bytes())
            .add_2bytes(self.identification.to_be_bytes())
            .add_2bytes({
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
                [flags | (frag_off_be[0] & 0x1f), frag_off_be[1]]
            })
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
        self.more_fragments || (0 != self.fragments_offset)
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
            source: [0; 4],
            destination: [0; 4],
            options_len: 0,
            options_buffer: [0; 40],
        }
    }
}

impl Debug for Ipv4Header {
    fn fmt(&self, f: &mut Formatter) -> Result<(), core::fmt::Error> {
        let mut s = f.debug_struct("Ipv4Header");
        s.field("ihl", &self.ihl());
        s.field(
            "differentiated_services_code_point",
            &self.differentiated_services_code_point,
        );
        s.field(
            "explicit_congestion_notification",
            &self.explicit_congestion_notification,
        );
        s.field("payload_len", &self.payload_len);
        s.field("identification", &self.identification);
        s.field("dont_fragment", &self.dont_fragment);
        s.field("more_fragments", &self.more_fragments);
        s.field("fragments_offset", &self.fragments_offset);
        s.field("time_to_live", &self.time_to_live);
        s.field("protocol", &self.protocol);
        s.field("header_checksum", &self.header_checksum);
        s.field("source", &self.source);
        s.field("destination", &self.destination);
        s.field("options", &self.options());
        s.finish()
    }
}

impl core::cmp::PartialEq for Ipv4Header {
    fn eq(&self, other: &Ipv4Header) -> bool {
        self.differentiated_services_code_point == other.differentiated_services_code_point
            && self.explicit_congestion_notification == other.explicit_congestion_notification
            && self.payload_len == other.payload_len
            && self.identification == other.identification
            && self.dont_fragment == other.dont_fragment
            && self.more_fragments == other.more_fragments
            && self.fragments_offset == other.fragments_offset
            && self.time_to_live == other.time_to_live
            && self.protocol == other.protocol
            && self.header_checksum == other.header_checksum
            && self.source == other.source
            && self.destination == other.destination
            && self.options_len == other.options_len
            && self.options() == other.options()
    }
}

impl core::cmp::Eq for Ipv4Header {}

#[cfg(test)]
mod test {
    use crate::{test_gens::*, *};
    use alloc::{format, vec::Vec};
    use arrayvec::ArrayVec;
    use proptest::prelude::*;
    use std::io::Cursor;

    #[test]
    fn default() {
        let default: Ipv4Header = Default::default();
        assert_eq!(5, default.ihl());
        assert_eq!(0, default.differentiated_services_code_point);
        assert_eq!(0, default.explicit_congestion_notification);
        assert_eq!(0, default.payload_len);
        assert_eq!(0, default.identification);
        assert_eq!(true, default.dont_fragment);
        assert_eq!(false, default.more_fragments);
        assert_eq!(0, default.fragments_offset);
        assert_eq!(0, default.time_to_live);
        assert_eq!(0, default.protocol);
        assert_eq!(0, default.header_checksum);
        assert_eq!([0; 4], default.source);
        assert_eq!([0; 4], default.destination);
        assert_eq!(default.options(), &[]);
    }

    proptest! {
        #[test]
        fn debug(input in ipv4_any()) {
            assert_eq!(&format!("Ipv4Header {{ ihl: {}, differentiated_services_code_point: {}, explicit_congestion_notification: {}, payload_len: {}, identification: {}, dont_fragment: {}, more_fragments: {}, fragments_offset: {}, time_to_live: {}, protocol: {}, header_checksum: {}, source: {:?}, destination: {:?}, options: {:?} }}",
                    input.ihl(),
                    input.differentiated_services_code_point,
                    input.explicit_congestion_notification,
                    input.payload_len,
                    input.identification,
                    input.dont_fragment,
                    input.more_fragments,
                    input.fragments_offset,
                    input.time_to_live,
                    input.protocol,
                    input.header_checksum,
                    input.source,
                    input.destination,
                    input.options()
                ),
                &format!("{:?}", input)
            );
        }
    }

    proptest! {
        #[test]
        fn eq(a in ipv4_any(),
              b in ipv4_any())
        {
            //check identity equality
            assert!(a == a);
            assert!(b == b);

            //check every field
            //differentiated_services_code_point
            assert_eq!(
                a.differentiated_services_code_point == b.differentiated_services_code_point,
                a == {
                    let mut other = a.clone();
                    other.differentiated_services_code_point = b.differentiated_services_code_point;
                    other
                }
            );
            //explicit_congestion_notification
            assert_eq!(
                a.explicit_congestion_notification == b.explicit_congestion_notification,
                a == {
                    let mut other = a.clone();
                    other.explicit_congestion_notification = b.explicit_congestion_notification;
                    other
                }
            );
            //payload_len
            assert_eq!(
                a.payload_len == b.payload_len,
                a == {
                    let mut other = a.clone();
                    other.payload_len = b.payload_len;
                    other
                }
            );
            //identification
            assert_eq!(
                a.identification == b.identification,
                a == {
                    let mut other = a.clone();
                    other.identification = b.identification;
                    other
                }
            );
            //dont_fragment
            assert_eq!(
                a.dont_fragment == b.dont_fragment,
                a == {
                    let mut other = a.clone();
                    other.dont_fragment = b.dont_fragment;
                    other
                }
            );
            //more_fragments
            assert_eq!(
                a.more_fragments == b.more_fragments,
                a == {
                    let mut other = a.clone();
                    other.more_fragments = b.more_fragments;
                    other
                }
            );
            //fragments_offset
            assert_eq!(
                a.fragments_offset == b.fragments_offset,
                a == {
                    let mut other = a.clone();
                    other.fragments_offset = b.fragments_offset;
                    other
                }
            );
            //time_to_live
            assert_eq!(
                a.time_to_live == b.time_to_live,
                a == {
                    let mut other = a.clone();
                    other.time_to_live = b.time_to_live;
                    other
                }
            );
            //protocol
            assert_eq!(
                a.protocol == b.protocol,
                a == {
                    let mut other = a.clone();
                    other.protocol = b.protocol;
                    other
                }
            );
            //header_checksum
            assert_eq!(
                a.header_checksum == b.header_checksum,
                a == {
                    let mut other = a.clone();
                    other.header_checksum = b.header_checksum;
                    other
                }
            );
            //source
            assert_eq!(
                a.source == b.source,
                a == {
                    let mut other = a.clone();
                    other.source = b.source;
                    other
                }
            );
            //destination
            assert_eq!(
                a.destination == b.destination,
                a == {
                    let mut other = a.clone();
                    other.destination = b.destination;
                    other
                }
            );

            //options
            assert_eq!(
                a.options() == b.options(),
                a == {
                    let mut other = a.clone();
                    other.set_options(b.options()).unwrap();
                    other
                }
            );
        }
    }

    proptest! {
        #[test]
        fn new(source_ip in prop::array::uniform4(any::<u8>()),
               dest_ip in prop::array::uniform4(any::<u8>()),
               ttl in any::<u8>(),
               payload_len in any::<u16>())
        {
            let result = Ipv4Header::new(
                payload_len,
                ttl,
                ip_number::UDP,
                source_ip,
                dest_ip
            );

            assert_eq!(result.differentiated_services_code_point, 0);
            assert_eq!(result.explicit_congestion_notification, 0);
            assert_eq!(result.payload_len, payload_len);
            assert_eq!(result.identification, 0);
            assert_eq!(result.dont_fragment, true);
            assert_eq!(result.more_fragments, false);
            assert_eq!(result.fragments_offset, 0);
            assert_eq!(result.time_to_live, ttl);
            assert_eq!(result.protocol, ip_number::UDP);
            assert_eq!(result.header_checksum, 0);
            assert_eq!(result.source, source_ip);
            assert_eq!(result.destination, dest_ip);
            assert_eq!(result.options(), &[]);
        }
    }

    proptest! {
        #[test]
        fn ihl(header in ipv4_any()) {
            assert_eq!(header.ihl(), (header.header_len() / 4) as u8);
        }
    }

    proptest! {
        #[test]
        fn header_len(header in ipv4_any()) {
            assert_eq!(header.header_len(), 20 + header.options().len());
        }
    }

    proptest! {
        #[test]
        fn total_len(header in ipv4_any()) {
            assert_eq!(header.total_len(), 20 + (header.options().len() as u16) + header.payload_len);
        }
    }

    #[test]
    fn set_payload_len() {
        let mut header = Ipv4Header::new(0, 0, ip_number::UDP, [0; 4], [0; 4]);

        //add options (to make sure they are included in the calculation)
        header.set_options(&[1, 2, 3, 4]).unwrap();

        //zero check
        assert!(header.set_payload_len(0).is_ok());
        assert_eq!(header.total_len(), 24);

        //max check
        const MAX: usize = (core::u16::MAX as usize) - Ipv4Header::MIN_LEN - 4;
        assert!(header.set_payload_len(MAX).is_ok());
        assert_eq!(header.total_len(), core::u16::MAX);

        const OVER_MAX: usize = MAX + 1;
        assert_eq!(
            header.set_payload_len(OVER_MAX),
            Err(ValueError::Ipv4PayloadLengthTooLarge(OVER_MAX))
        );
    }

    proptest! {
        #[test]
        fn max_payload_len(header in ipv4_any()) {
            assert_eq!(header.max_payload_len(), core::u16::MAX - 20 - (header.options().len() as u16));
        }
    }

    #[test]
    fn set_options() {
        //length of 1
        {
            let mut header: Ipv4Header = Default::default();
            let options = [1, 2, 3, 4];
            assert_eq!(header.set_options(&options), Ok(()));

            assert_eq!(&options, header.options());
            assert_eq!(24, header.header_len());
            assert_eq!(24, header.total_len());
            assert_eq!(6, header.ihl());

            //length 0
            assert_eq!(header.set_options(&[]), Ok(()));

            assert_eq!(&options[..0], header.options());
            assert_eq!(20, header.header_len());
            assert_eq!(20, header.total_len());
            assert_eq!(5, header.ihl());
        }
        //maximum length (40)
        {
            let mut header: Ipv4Header = Default::default();
            let options = [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            ];
            assert_eq!(header.set_options(&options), Ok(()));

            assert_eq!(&options[..], header.options());
            assert_eq!(60, header.header_len());
            assert_eq!(60, header.total_len());
            assert_eq!(15, header.ihl());
        }
        //errors
        {
            let buffer: [u8; 50] = [0; 50];
            for len in &[
                1usize, 2, 3, //unaligned
                5, 6, 7, 41, 44, //over max
            ] {
                let mut header: Ipv4Header = Default::default();

                //expect an error
                use self::ValueError::Ipv4OptionsLengthBad;
                assert_eq!(
                    Err(Ipv4OptionsLengthBad(*len)),
                    header.set_options(&buffer[..*len])
                );

                //check value was not taken
                assert_eq!(&buffer[..0], header.options());
                assert_eq!(20, header.header_len());
                assert_eq!(20, header.total_len());
                assert_eq!(5, header.ihl());
            }
        }
    }

    proptest! {
        #[test]
        #[allow(deprecated)]
        fn read_from_slice(ref input in ipv4_any()) {
            //serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len());
            input.write_raw(&mut buffer).unwrap();
            assert_eq!(input.header_len(), buffer.len());

            //deserialize (read_from_slice)
            let result = Ipv4Header::read_from_slice(&buffer).unwrap();
            assert_eq!(input, &result.0);
            assert_eq!(&buffer[usize::from(input.header_len())..], result.1);
        }
    }

    proptest! {
        #[test]
        fn from_slice(header in ipv4_any()) {
            use err::ipv4::HeaderError::*;
            use err::ipv4::HeaderSliceError::*;

            // ok
            {
                let mut buffer = ArrayVec::<u8, { Ipv4Header::MAX_LEN + 1 }>::new();
                buffer.try_extend_from_slice(&header.to_bytes().unwrap()).unwrap();
                buffer.try_extend_from_slice(&[1]).unwrap();

                let (actual_header, actual_rest) = Ipv4Header::from_slice(&buffer).unwrap();
                assert_eq!(actual_header, header);
                assert_eq!(actual_rest, &[1]);
            }

            // unexpected end of slice
            {
                let buffer = header.to_bytes().unwrap();
                for len in 0..header.header_len() {
                    assert_eq!(
                        Ipv4Header::from_slice(&buffer[..len]),
                        Err(Len(err::LenError{
                            required_len: if len < Ipv4Header::MIN_LEN {
                                Ipv4Header::MIN_LEN
                            } else {
                                header.header_len()
                            },
                            len: len,
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv4Header,
                            layer_start_offset: 0,
                        }))
                    );
                }
            }

            // version error
            for version_number in 0u8..0b1111u8 {
                if 4 != version_number {
                    let mut buffer = header.to_bytes().unwrap();
                    // inject the bad ihl
                    buffer[0] = (version_number << 4) | (buffer[0] & 0b1111);
                    // expect an error
                    assert_eq!(
                        Ipv4Header::from_slice(&buffer).unwrap_err(),
                        Content(UnexpectedVersion{
                            version_number,
                        })
                    );
                }
            }

            // ihl too small error
            for ihl in 0u8..5u8 {
                let mut buffer = header.to_bytes().unwrap();
                // inject the bad ihl
                buffer[0] = (4 << 4) | ihl;
                // expect an error
                assert_eq!(
                    Ipv4Header::from_slice(&buffer).unwrap_err(),
                    Content(HeaderLengthSmallerThanHeader{
                        ihl,
                    })
                );
            }

            // total length too small error
            for total_length in 0..header.header_len() {
                let mut buffer = header.to_bytes().unwrap();
                // inject total length smaller then the header length
                let tl_be = (total_length as u16).to_be_bytes();
                buffer[2] = tl_be[0];
                buffer[3] = tl_be[1];
                // expect an error
                assert_eq!(
                    Ipv4Header::from_slice(&buffer).unwrap_err(),
                    Content(TotalLengthSmallerThanHeader{
                        total_length: total_length as u16,
                        min_expected_length: header.header_len() as u16,
                    })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn read_and_read_without_version(header in ipv4_any()) {
            use err::ipv4::HeaderError::*;
            use std::io::Cursor;

            // ok
            {
                let buffer = header.to_bytes().unwrap();

                // read
                {
                    let mut cursor = Cursor::new(&buffer);
                    let actual_header = Ipv4Header::read(&mut cursor).unwrap();
                    assert_eq!(actual_header, header);
                    assert_eq!(cursor.position(), header.header_len() as u64);
                }
                // read_without_version
                {
                    let mut cursor = Cursor::new(&buffer[1..]);
                    let actual_header = Ipv4Header::read_without_version(&mut cursor, buffer[0]).unwrap();
                    assert_eq!(actual_header, header);
                    assert_eq!(cursor.position(), (header.header_len() - 1) as u64);
                }
            }

            // io error
            {
                let buffer = header.to_bytes().unwrap();
                for len in 0..header.header_len() {
                    // read
                    {
                        let mut cursor = Cursor::new(&buffer[..len]);
                        let err = Ipv4Header::read(&mut cursor).unwrap_err();
                        assert!(err.io_error().is_some());
                    }

                    // read_without_version
                    if len > 0 {
                        let mut cursor = Cursor::new(&buffer[1..len]);
                        let err = Ipv4Header::read_without_version(&mut cursor, buffer[0]).unwrap_err();
                        assert!(err.io_error().is_some());
                    }
                }
            }

            // version error
            for version_number in 0u8..0b1111u8 {
                if 4 != version_number {
                    let mut buffer = header.to_bytes().unwrap();
                    // inject the bad version number
                    buffer[0] = (version_number << 4) | (buffer[0] & 0b1111);

                    // expect an error
                    // read
                    {
                        let mut cursor = Cursor::new(&buffer[..]);
                        let err = Ipv4Header::read(&mut cursor)
                            .unwrap_err()
                            .content_error()
                            .unwrap();
                        assert_eq!(err, UnexpectedVersion{ version_number });
                    }

                    // read_without_version skipped as version is not checked
                }
            }

            // ihl too small error
            for ihl in 0u8..5u8 {
                let mut buffer = header.to_bytes().unwrap();
                // inject the bad ihl
                buffer[0] = (4 << 4) | ihl;
                // expect an error
                // read
                {
                    let mut cursor = Cursor::new(&buffer[..]);
                    let err = Ipv4Header::read(&mut cursor)
                        .unwrap_err()
                        .content_error()
                        .unwrap();
                    assert_eq!(err, HeaderLengthSmallerThanHeader{ ihl });
                }

                // read_without_version
                {
                    let mut cursor = Cursor::new(&buffer[1..]);
                    let err = Ipv4Header::read_without_version(&mut cursor, buffer[0])
                        .unwrap_err()
                        .content_error()
                        .unwrap();
                    assert_eq!(err, HeaderLengthSmallerThanHeader{ ihl });
                }
            }

            // total length too small error
            for total_length in 0..header.header_len() {
                let mut buffer = header.to_bytes().unwrap();
                // inject total length smaller then the header length
                let tl_be = (total_length as u16).to_be_bytes();
                buffer[2] = tl_be[0];
                buffer[3] = tl_be[1];

                // expect an error
                let expected_err = TotalLengthSmallerThanHeader{
                    total_length: total_length as u16,
                    min_expected_length: header.header_len() as u16,
                };

                // read
                {
                    let mut cursor = Cursor::new(&buffer[..]);
                    let err = Ipv4Header::read(&mut cursor)
                        .unwrap_err()
                        .content_error()
                        .unwrap();
                    assert_eq!(err, expected_err);
                }

                // read_without_version
                {
                    let mut cursor = Cursor::new(&buffer[1..]);
                    let err = Ipv4Header::read_without_version(&mut cursor, buffer[0])
                        .unwrap_err()
                        .content_error()
                        .unwrap();
                    assert_eq!(err, expected_err);
                }
            }
        }
    }

    proptest! {
        #[test]
        fn check_ranges(
            base_header in ipv4_any(),
            bad_dscp in 0b100_0000u8..=u8::MAX,
            bad_ecn in 0b100..=u8::MAX,
            bad_frag_offset in 0b0010_0000_0000_0000u16..=u16::MAX
        ) {
            use crate::ErrorField::*;
            use crate::ValueError::*;

            fn test_range_methods(input: &Ipv4Header, expected: ValueError) {

                // check_ranges
                assert_eq!(expected.clone(), input.check_ranges().unwrap_err());

                //calc_header_checksum
                assert_eq!(expected.clone(), input.calc_header_checksum().unwrap_err());

                //write
                {
                    let mut buffer: Vec<u8> = Vec::new();
                    let result = input.write(&mut buffer);
                    assert_eq!(0, buffer.len());
                    assert_eq!(Some(expected.clone()), result.unwrap_err().value_error());
                }

                //write_raw
                {
                    let mut buffer: Vec<u8> = Vec::new();
                    let result = input.write_raw(&mut buffer);
                    assert_eq!(0, buffer.len());
                    assert_eq!(Some(expected.clone()), result.unwrap_err().value_error());
                }
            }
            //dscp
            {
                let value = {
                    let mut value = base_header.clone();
                    value.differentiated_services_code_point = bad_dscp;
                    value
                };
                test_range_methods(
                    &value,
                    U8TooLarge {
                        value: bad_dscp,
                        max: 0b11_1111,
                        field: Ipv4Dscp,
                    },
                );
            }
            //ecn
            {
                let value = {
                    let mut value = base_header.clone();
                    value.explicit_congestion_notification = bad_ecn;
                    value
                };
                test_range_methods(
                    &value,
                    U8TooLarge {
                        value: bad_ecn,
                        max: 0b11,
                        field: Ipv4Ecn,
                    },
                );
            }
            // fragmentation offset
            {
                let value = {
                    let mut value = base_header.clone();
                    value.fragments_offset = bad_frag_offset;
                    value
                };
                test_range_methods(
                    &value,
                    U16TooLarge {
                        value: bad_frag_offset,
                        max: 0x1FFF,
                        field: Ipv4FragmentsOffset,
                    },
                );
            }
            // payload len
            {
                let max_len = u16::MAX - (base_header.header_len() as u16);
                let value = {
                    let mut value = base_header.clone();
                    value.payload_len = max_len + 1;
                    value
                };
                test_range_methods(
                    &value,
                    U16TooLarge {
                        value: max_len + 1,
                        max: max_len,
                        field: Ipv4PayloadLength,
                    },
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write(ref base_header in ipv4_any()) {
            use std::io::Cursor;

            let header = {
                let mut header = base_header.clone();
                // set the header checksum to something else to
                // ensure it is calculated during the write call
                header.header_checksum = 0;
                header
            };

            // normal write
            {
                //serialize
                let buffer = {
                    let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
                    header.write(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(header.header_len(), buffer.len());

                //deserialize
                let mut cursor = Cursor::new(&buffer);
                let result = Ipv4Header::read(&mut cursor).unwrap();
                assert_eq!(header.header_len(), cursor.position() as usize);

                //check equivalence (with calculated checksum)
                let header_with_checksum = {
                    let mut h = header.clone();
                    h.header_checksum = h.calc_header_checksum().unwrap();
                    h
                };
                assert_eq!(header_with_checksum, result);
            }

            // io error
            for len in 0..header.header_len() {
                let mut buffer = [0u8; Ipv4Header::MAX_LEN];
                let mut cursor = Cursor::new(&mut buffer[..len]);
                assert!(
                    header.write(&mut cursor).unwrap_err().io_error().is_some()
                );
            }

            // range error
            {
                let err = {
                    let mut header = base_header.clone();
                    header.payload_len = u16::MAX;
                    let mut buffer = Vec::new();
                    header.write(&mut buffer).unwrap_err().value_error().unwrap()
                };
                assert_eq!(err, ValueError::U16TooLarge {
                    value: u16::MAX,
                    max: u16::MAX - (base_header.header_len() as u16),
                    field: ErrorField::Ipv4PayloadLength
                });
            }
        }
    }

    proptest! {
        #[test]
        fn write_raw(base_header in ipv4_any()) {
            // normal write
            {
                //serialize
                let buffer = {
                    let mut buffer: Vec<u8> = Vec::with_capacity(base_header.header_len());
                    base_header.write_raw(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(base_header.header_len(), buffer.len());

                // decode and check for equality
                assert_eq!(
                    Ipv4Header::from_slice(&buffer).unwrap().0,
                    base_header
                );
            }

            // io error
            for len in 0..base_header.header_len() {
                let mut buffer = [0u8; Ipv4Header::MAX_LEN];
                let mut cursor = Cursor::new(&mut buffer[..len]);
                assert!(
                    base_header.write_raw(&mut cursor).unwrap_err().io_error().is_some()
                );
            }

            // range error
            {
                let err = {
                    let mut header = base_header.clone();
                    header.payload_len = u16::MAX;
                    let mut buffer = Vec::new();
                    header.write_raw(&mut buffer).unwrap_err().value_error().unwrap()
                };
                assert_eq!(err, ValueError::U16TooLarge {
                    value: u16::MAX,
                    max: u16::MAX - (base_header.header_len() as u16),
                    field: ErrorField::Ipv4PayloadLength
                });
            }
        }
    }

    proptest! {
        #[test]
        fn to_bytes(base_header in ipv4_any()) {
            // normal write
            {
                let bytes = base_header.to_bytes().unwrap();
                assert_eq!(
                    base_header,
                    Ipv4HeaderSlice::from_slice(&bytes).unwrap().to_header()
                );
            }
            // range error
            {
                let result = {
                    let mut header = base_header.clone();
                    header.payload_len = u16::MAX;
                    header.to_bytes()
                };
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn calc_header_checksum() {
        let base: Ipv4Header = Ipv4Header::new(
            40,
            4, // ttl
            ip_number::UDP,
            [192, 168, 1, 1],   // source
            [212, 10, 11, 123], // destination
        );

        //without options
        {
            //dont_fragment && !more_fragments
            let header = base.clone();
            assert_eq!(0xd582, header.calc_header_checksum().unwrap());
            // !dont_fragment && more_fragments
            let header = {
                let mut header = base.clone();
                header.dont_fragment = false;
                header.more_fragments = true;
                header
            };
            assert_eq!(0xf582, header.calc_header_checksum().unwrap());
        }
        //with options
        {
            let header = {
                let mut header = base.clone();
                header.payload_len = 40 - 8;
                header.set_options(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
                header
            };
            assert_eq!(0xc36e, header.calc_header_checksum().unwrap());
        }
    }

    #[test]
    fn is_fragmenting_payload() {
        // not fragmenting
        {
            let mut header: Ipv4Header = Default::default();
            header.fragments_offset = 0;
            header.more_fragments = false;
            assert_eq!(false, header.is_fragmenting_payload());
        }

        // fragmenting based on offset
        {
            let mut header: Ipv4Header = Default::default();
            header.fragments_offset = 1;
            header.more_fragments = false;
            assert!(header.is_fragmenting_payload());
        }

        // fragmenting based on more_fragments
        {
            let mut header: Ipv4Header = Default::default();
            header.fragments_offset = 0;
            header.more_fragments = true;
            assert!(header.is_fragmenting_payload());
        }
    }
}
