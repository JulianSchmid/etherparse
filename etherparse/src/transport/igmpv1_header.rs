use crate::*;

/// Membership Query message type.
pub const IGMPV1_TYPE_MEMBERSHIP_QUERY: u8 = 0x11;
/// Version 1 Membership Report message type.
pub const IGMPV1_TYPE_MEMBERSHIP_REPORT: u8 = 0x12;

/// A header of an IGMPv1 packet.
///
/// IGMPv1 has a fixed header size of 8 bytes:
/// type, reserved, checksum and group address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmpv1Header {
    /// IGMP message type.
    pub igmp_type: u8,
    /// Reserved/unused octet.
    pub reserved: u8,
    /// Checksum in the IGMP header.
    pub checksum: u16,
    /// Group address.
    pub group_address: [u8; 4],
}

impl Igmpv1Header {
    /// Number of bytes/octets an [`Igmpv1Header`] takes up in serialized form.
    pub const LEN: usize = 8;

    /// Constructs an [`Igmpv1Header`] with reserved & checksum set to 0.
    #[inline]
    pub fn new(igmp_type: u8, group_address: [u8; 4]) -> Igmpv1Header {
        Igmpv1Header {
            igmp_type,
            reserved: 0,
            checksum: 0,
            group_address,
        }
    }

    /// Creates an [`Igmpv1Header`] with a checksum calculated from the header values.
    #[inline]
    pub fn with_checksum(igmp_type: u8, group_address: [u8; 4]) -> Igmpv1Header {
        let mut result = Igmpv1Header::new(igmp_type, group_address);
        result.update_checksum();
        result
    }

    /// Reads an IGMPv1 header from a slice directly and returns a tuple containing
    /// the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Igmpv1Header, &[u8]), err::LenError> {
        if slice.len() < Self::LEN {
            return Err(err::LenError {
                required_len: Self::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmpv1,
                layer_start_offset: 0,
            });
        }

        Ok((
            Igmpv1Header::from_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            &slice[Self::LEN..],
        ))
    }

    /// Read an [`Igmpv1Header`] from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 8]) -> Igmpv1Header {
        Igmpv1Header {
            igmp_type: bytes[0],
            reserved: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            group_address: [bytes[4], bytes[5], bytes[6], bytes[7]],
        }
    }

    /// Reads an IGMPv1 header from the given reader.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + Sized>(
        reader: &mut T,
    ) -> Result<Igmpv1Header, std::io::Error> {
        let mut bytes = [0u8; Self::LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Igmpv1Header::from_bytes(bytes))
    }

    /// Write the IGMPv1 header to the given writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Length in bytes/octets of this header type.
    #[inline]
    pub const fn header_len(&self) -> usize {
        Self::LEN
    }

    /// Calculates and returns the checksum based on the current header values.
    #[inline]
    pub fn calc_checksum(&self) -> u16 {
        checksum::Sum16BitWords::new()
            .add_2bytes([self.igmp_type, self.reserved])
            .add_4bytes(self.group_address)
            .ones_complement()
            .to_be()
    }

    /// Calculates and updates the checksum in the header.
    #[inline]
    pub fn update_checksum(&mut self) {
        self.checksum = self.calc_checksum();
    }

    /// Converts the header to on-the-wire bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 8] {
        let checksum_be = self.checksum.to_be_bytes();
        [
            self.igmp_type,
            self.reserved,
            checksum_be[0],
            checksum_be[1],
            self.group_address[0],
            self.group_address[1],
            self.group_address[2],
            self.group_address[3],
        ]
    }
}

#[cfg(test)]
mod test {
    use crate::{
        err::{Layer, LenError},
        *,
    };
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;
    #[cfg(feature = "std")]
    use std::io::Cursor;

    #[test]
    fn constants() {
        assert_eq!(8, Igmpv1Header::LEN);
        assert_eq!(0x11, IGMPV1_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(0x12, IGMPV1_TYPE_MEMBERSHIP_REPORT);
    }

    proptest! {
        #[test]
        fn new(igmp_type in any::<u8>(), group_address in any::<[u8;4]>()) {
            assert_eq!(
                Igmpv1Header {
                    igmp_type,
                    reserved: 0,
                    checksum: 0,
                    group_address,
                },
                Igmpv1Header::new(igmp_type, group_address)
            );
        }
    }

    proptest! {
        #[test]
        fn with_checksum(igmp_type in any::<u8>(), group_address in any::<[u8;4]>()) {
            let header = Igmpv1Header::with_checksum(igmp_type, group_address);
            assert_eq!(igmp_type, header.igmp_type);
            assert_eq!(0, header.reserved);
            assert_eq!(group_address, header.group_address);
            assert_eq!(header.calc_checksum(), header.checksum);
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16)
        ) {
            let checksum_be = checksum.to_be_bytes();
            let mut bytes = vec![
                igmp_type,
                reserved,
                checksum_be[0],
                checksum_be[1],
                group_address[0],
                group_address[1],
                group_address[2],
                group_address[3],
            ];
            bytes.extend_from_slice(&suffix);

            let (actual, rest) = Igmpv1Header::from_slice(&bytes).unwrap();
            assert_eq!(
                Igmpv1Header {
                    igmp_type,
                    reserved,
                    checksum,
                    group_address,
                },
                actual
            );
            assert_eq!(suffix.as_slice(), rest);

            for bad_len in 0..Igmpv1Header::LEN {
                assert_eq!(
                    Igmpv1Header::from_slice(&bytes[..bad_len]),
                    Err(LenError{
                        required_len: Igmpv1Header::LEN,
                        len: bad_len,
                        len_source: LenSource::Slice,
                        layer: Layer::Igmpv1,
                        layer_start_offset: 0,
                    })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_bytes(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
        ) {
            let checksum_be = checksum.to_be_bytes();
            let bytes = [
                igmp_type,
                reserved,
                checksum_be[0],
                checksum_be[1],
                group_address[0],
                group_address[1],
                group_address[2],
                group_address[3],
            ];

            assert_eq!(
                Igmpv1Header {
                    igmp_type,
                    reserved,
                    checksum,
                    group_address,
                },
                Igmpv1Header::from_bytes(bytes)
            );
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn read(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..16)
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };
            let mut bytes = input.to_bytes().to_vec();
            bytes.extend_from_slice(&suffix);

            let mut cursor = Cursor::new(&bytes);
            let actual = Igmpv1Header::read(&mut cursor).unwrap();
            assert_eq!(input, actual);
            assert_eq!(Igmpv1Header::LEN as u64, cursor.position());

            for bad_len in 0..Igmpv1Header::LEN {
                let mut c = Cursor::new(&bytes[..bad_len]);
                assert!(Igmpv1Header::read(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn write(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>()
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };

            let mut out = Vec::new();
            input.write(&mut out).unwrap();
            assert_eq!(input.to_bytes().as_slice(), out.as_slice());

            for bad_len in 0..Igmpv1Header::LEN {
                let mut buf = [0u8; Igmpv1Header::LEN];
                let mut c = Cursor::new(&mut buf[..bad_len]);
                assert!(input.write(&mut c).is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>()
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };
            assert_eq!(Igmpv1Header::LEN, input.header_len());
        }
    }

    proptest! {
        #[test]
        fn calc_checksum(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>()
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };

            let expected = checksum::Sum16BitWords::new()
                .add_2bytes([igmp_type, reserved])
                .add_4bytes(group_address)
                .ones_complement()
                .to_be();
            assert_eq!(expected, input.calc_checksum());
        }
    }

    proptest! {
        #[test]
        fn update_checksum(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>()
        ) {
            let mut input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };
            input.update_checksum();
            assert_eq!(input.calc_checksum(), input.checksum);
        }
    }

    proptest! {
        #[test]
        fn to_bytes(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>()
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };
            let checksum_be = checksum.to_be_bytes();
            assert_eq!(
                [
                    igmp_type,
                    reserved,
                    checksum_be[0],
                    checksum_be[1],
                    group_address[0],
                    group_address[1],
                    group_address[2],
                    group_address[3],
                ],
                input.to_bytes()
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>()
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn debug(
            igmp_type in any::<u8>(),
            reserved in any::<u8>(),
            checksum in any::<u16>(),
            group_address in any::<[u8;4]>()
        ) {
            let input = Igmpv1Header {
                igmp_type,
                reserved,
                checksum,
                group_address,
            };
            assert_eq!(
                format!(
                    "Igmpv1Header {{ igmp_type: {}, reserved: {}, checksum: {}, group_address: {:?} }}",
                    igmp_type,
                    reserved,
                    checksum,
                    group_address,
                ),
                format!("{:?}", input)
            );
        }
    }
}
