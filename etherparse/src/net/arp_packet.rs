use arrayvec::ArrayVec;
use err::arp::ArpNewError;

use crate::*;
use core::mem::MaybeUninit;

/// "Address Resolution Protocol" Packet.
#[derive(Clone)]
pub struct ArpPacket {
    /// Network link protocol type (e.g. `ArpHardwareId::ETHERNET`).
    pub hw_addr_type: ArpHardwareId,

    /// Protocol for which the ARP request is intended (e.g. `EtherType::IPV4`).
    pub proto_addr_type: EtherType,

    /// Length (in octets) of a hardware address (e.g. 6 for Ethernet).
    hw_addr_size: u8,

    /// Length (in octets) of internetwork addresses (e.g. 4 for IPv4 or 16 for IPv6).
    proto_addr_size: u8,

    /// Specifies the operation that the sender is performing
    pub operation: ArpOperation,

    /// Buffer containing the sender hardware address (e.g. MAC address).
    sender_hw_addr_buf: [MaybeUninit<u8>; 0xff],

    /// Buffer containing the sender protocol address (e.g. IPv4 address).
    sender_protocol_addr_buf: [MaybeUninit<u8>; 0xff],

    /// Buffer containing the target hardware address (e.g. MAC address).
    target_hw_addr_buf: [MaybeUninit<u8>; 0xff],

    /// Buffer containing the target protocol address (e.g. IPv4 address)..
    target_protocol_addr_buf: [MaybeUninit<u8>; 0xff],
}

impl ArpPacket {
    /// Maximum length of an ARP packet in bytes/octets.
    ///
    /// This number is calculated by taking the maximum values
    /// that `hw_addr_size`(255/u8::MAX) & `proto_addr_size` (255/u8::MAX)
    /// can take and calculate the maximum packet size from that.
    pub const MAX_LEN: usize = 8 + 2 * 255 + 2 * 255;

    /// Create a new ARP packet with the given values.
    pub const fn new(
        hw_addr_type: ArpHardwareId,
        proto_addr_type: EtherType,
        operation: ArpOperation,
        sender_hw_addr: &[u8],
        sender_protocol_addr: &[u8],
        target_hw_addr: &[u8],
        target_protocol_addr: &[u8],
    ) -> Result<ArpPacket, ArpNewError> {
        if sender_hw_addr.len() != target_hw_addr.len() {
            return Err(ArpNewError::HwAddrLenInconsistent(
                sender_hw_addr.len(),
                target_hw_addr.len(),
            ));
        }
        if sender_protocol_addr.len() != target_protocol_addr.len() {
            return Err(ArpNewError::ProtocolAddrLenInconsistent(
                sender_protocol_addr.len(),
                target_protocol_addr.len(),
            ));
        }
        if sender_hw_addr.len() > 255 {
            return Err(ArpNewError::HwAddrLenTooBig(sender_hw_addr.len()));
        }
        if sender_protocol_addr.len() > 255 {
            return Err(ArpNewError::ProtocolAddrLenTooBig(
                sender_protocol_addr.len(),
            ));
        }
        Ok(ArpPacket {
            hw_addr_type,
            proto_addr_type,
            // cast ok as we verfied the len to be less equal then 255.
            hw_addr_size: sender_hw_addr.len() as u8,
            // cast ok as we verfied the len to be less equal then 255.
            proto_addr_size: sender_protocol_addr.len() as u8,
            operation,
            sender_hw_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * sender_hw_addr.len() is guranteed to be <= 255 (checked in if above)
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        sender_hw_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        sender_hw_addr.len(),
                    );
                }
                buf
            },
            sender_protocol_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * sender_protocol_addr.len() is guranteed to be <= 255 (checked in if above)
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        sender_protocol_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        sender_protocol_addr.len(),
                    );
                }
                buf
            },
            target_hw_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * target_hw_addr.len() is guranteed to be <= 255 (checked in if above)
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        target_hw_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        target_hw_addr.len(),
                    );
                }
                buf
            },
            target_protocol_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * target_protocol_addr.len() is guranteed to be <= 255 (checked in if above)
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        target_protocol_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        target_protocol_addr.len(),
                    );
                }
                buf
            },
        })
    }

    /// Create a new ARP packet with the given values without checking
    /// hardware & protocol address sizes.
    ///
    /// # Safety
    ///
    /// The caller must gurantee that
    ///
    /// * `sender_hw_addr` & `target_hw_addr` have the same length and the length must be smaller or equal than 255.
    /// * `sender_protocol_addr` & `target_protocol_addr` have the same length and the length must be smaller or equal than 255.
    ///
    /// The gurantees the caller must fullfill are equal to the following
    /// preconditions:
    ///
    /// * `sender_hw_addr.len() == target_hw_addr.len()`
    /// * `sender_hw_addr.len() <= 255`
    /// * `target_hw_addr.len() <= 255`
    /// * `sender_protocol_addr.len() == target_protocol_addr.len()`
    /// * `sender_protocol_addr.len() <= 255`
    /// * `target_protocol_addr.len() <= 255`
    pub const unsafe fn new_unchecked(
        hw_addr_type: ArpHardwareId,
        proto_addr_type: EtherType,
        operation: ArpOperation,
        sender_hw_addr: &[u8],
        sender_protocol_addr: &[u8],
        target_hw_addr: &[u8],
        target_protocol_addr: &[u8],
    ) -> ArpPacket {
        debug_assert!(sender_hw_addr.len() == target_hw_addr.len());
        debug_assert!(sender_protocol_addr.len() == target_protocol_addr.len());
        debug_assert!(sender_hw_addr.len() <= 255);
        debug_assert!(sender_protocol_addr.len() <= 255);

        ArpPacket {
            hw_addr_type,
            proto_addr_type,
            // cast ok as we verfied the len to be less equal then 255.
            hw_addr_size: sender_hw_addr.len() as u8,
            // cast ok as we verfied the len to be less equal then 255.
            proto_addr_size: sender_protocol_addr.len() as u8,
            operation,
            sender_hw_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * the caller must gurantee that sender_hw_addr.len() is <= 255
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        sender_hw_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        sender_hw_addr.len(),
                    );
                }
                buf
            },
            sender_protocol_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * the caller must gurantee that sender_protocol_addr.len() is <= 255
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        sender_protocol_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        sender_protocol_addr.len(),
                    );
                }
                buf
            },
            target_hw_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * the caller must gurantee that target_hw_addr.len() is <= 255
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        target_hw_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        target_hw_addr.len(),
                    );
                }
                buf
            },
            target_protocol_addr_buf: {
                let mut buf: [MaybeUninit<u8>; 255] = [const { MaybeUninit::uninit() }; 255];
                // SAFETY: Safe as
                // * the caller must gurantee that target_protocol_addr.len() is <= 255
                // * memory areas guranteed to be non overlapping (buf created in this function).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        target_protocol_addr.as_ptr(),
                        buf.as_mut_ptr() as *mut u8,
                        target_protocol_addr.len(),
                    );
                }
                buf
            },
        }
    }

    /// Reads an ARP packet from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<ArpPacket, err::LenError> {
        ArpPacketSlice::from_slice(slice).map(|v| v.to_packet())
    }

    /// Length (in octets) of a hardware address (e.g. 6 for Ethernet).
    #[inline]
    pub const fn hw_addr_size(&self) -> u8 {
        self.hw_addr_size
    }

    /// Length (in octets) of internetwork addresses (e.g. 4 for IPv4 or 16 for IPv6).
    #[inline]
    pub const fn proto_addr_size(&self) -> u8 {
        self.proto_addr_size
    }

    /// Sender hardware address (e.g. MAC address).
    #[inline]
    pub const fn sender_hw_addr(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.sender_hw_addr_buf.as_ptr() as *const u8,
                self.hw_addr_size as usize,
            )
        }
    }

    /// Sender protocol address (e.g. IPv4 address).
    #[inline]
    pub const fn sender_protocol_addr(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.sender_protocol_addr_buf.as_ptr() as *const u8,
                self.proto_addr_size as usize,
            )
        }
    }

    /// Target hardware address (e.g. MAC address).
    #[inline]
    pub const fn target_hw_addr(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.target_hw_addr_buf.as_ptr() as *const u8,
                self.hw_addr_size as usize,
            )
        }
    }

    /// Buffer containing the target protocol address (e.g. IPv4 address)..
    #[inline]
    pub const fn target_protocol_addr(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.target_protocol_addr_buf.as_ptr() as *const u8,
                self.proto_addr_size as usize,
            )
        }
    }

    /// Serialized length of this ARP packet.
    #[inline]
    pub fn packet_len(&self) -> usize {
        8 + usize::from(self.hw_addr_size) * 2 + usize::from(self.proto_addr_size) * 2
    }

    /// Returns the serialized header.
    #[inline]
    pub fn to_bytes(&self) -> ArrayVec<u8, { ArpPacket::MAX_LEN }> {
        let hw_addr_type = self.hw_addr_type.0.to_be_bytes();
        let proto_addr_type = self.proto_addr_type.0.to_be_bytes();
        let operation = self.operation.0.to_be_bytes();
        let mut result = ArrayVec::<u8, { ArpPacket::MAX_LEN }>::new_const();
        result.extend([
            hw_addr_type[0],
            hw_addr_type[1],
            proto_addr_type[0],
            proto_addr_type[1],
            self.hw_addr_size,
            self.proto_addr_size,
            operation[0],
            operation[1],
        ]);
        result.try_extend_from_slice(self.sender_hw_addr()).unwrap();
        result
            .try_extend_from_slice(self.sender_protocol_addr())
            .unwrap();
        result.try_extend_from_slice(self.target_hw_addr()).unwrap();
        result
            .try_extend_from_slice(self.target_protocol_addr())
            .unwrap();
        result
    }

    /// Writes the header to the given writer.
    #[cfg(feature = "std")]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + std::io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<ArpPacket, std::io::Error> {
        let mut start = [0u8; 8];
        reader.read_exact(&mut start[..])?;

        let mut result = ArpPacket {
            hw_addr_type: ArpHardwareId(u16::from_be_bytes([start[0], start[1]])),
            proto_addr_type: EtherType(u16::from_be_bytes([start[2], start[3]])),
            hw_addr_size: start[4],
            proto_addr_size: start[5],
            operation: ArpOperation(u16::from_be_bytes([start[6], start[7]])),
            sender_hw_addr_buf: [const { MaybeUninit::uninit() }; 255],
            sender_protocol_addr_buf: [const { MaybeUninit::uninit() }; 255],
            target_hw_addr_buf: [const { MaybeUninit::uninit() }; 255],
            target_protocol_addr_buf: [const { MaybeUninit::uninit() }; 255],
        };

        {
            // SAFETY: Safe as the maximum u8 value is equal to the array size 255.
            let sender_hw_addr_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    result.sender_hw_addr_buf.as_mut_ptr() as *mut u8,
                    result.hw_addr_size as usize,
                )
            };
            reader.read_exact(sender_hw_addr_slice)?;
        }
        {
            // SAFETY: Safe as the maximum u8 value is equal to the array size 255.
            let sender_protocol_addr = unsafe {
                core::slice::from_raw_parts_mut(
                    result.sender_protocol_addr_buf.as_mut_ptr() as *mut u8,
                    result.proto_addr_size as usize,
                )
            };
            reader.read_exact(sender_protocol_addr)?;
        }
        {
            // SAFETY: Safe as the maximum u8 value is equal to the array size 255.
            let target_hw_addr = unsafe {
                core::slice::from_raw_parts_mut(
                    result.target_hw_addr_buf.as_mut_ptr() as *mut u8,
                    result.hw_addr_size as usize,
                )
            };
            reader.read_exact(target_hw_addr)?;
        }
        {
            // SAFETY: Safe as the maximum u8 value is equal to the array size 255.
            let target_protocol_addr = unsafe {
                core::slice::from_raw_parts_mut(
                    result.target_protocol_addr_buf.as_mut_ptr() as *mut u8,
                    result.proto_addr_size as usize,
                )
            };
            reader.read_exact(target_protocol_addr)?;
        }

        Ok(result)
    }
}

impl core::fmt::Debug for ArpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArpPacket")
            .field("hw_addr_type", &self.hw_addr_type)
            .field("proto_addr_type", &self.proto_addr_type)
            .field("hw_addr_size", &self.hw_addr_size)
            .field("proto_addr_size", &self.proto_addr_size)
            .field("operation", &self.operation)
            .field("sender_hw_addr", &self.sender_hw_addr())
            .field("sender_protocol_addr", &self.sender_protocol_addr())
            .field("target_hw_addr", &self.target_hw_addr())
            .field("target_protocol_addr", &self.target_protocol_addr())
            .finish()
    }
}

impl core::cmp::PartialEq for ArpPacket {
    fn eq(&self, other: &Self) -> bool {
        self.hw_addr_type == other.hw_addr_type
            && self.proto_addr_type == other.proto_addr_type
            && self.hw_addr_size == other.hw_addr_size
            && self.proto_addr_size == other.proto_addr_size
            && self.operation == other.operation
            && self.sender_hw_addr() == other.sender_hw_addr()
            && self.sender_protocol_addr() == other.sender_protocol_addr()
            && self.target_hw_addr() == other.target_hw_addr()
            && self.target_protocol_addr() == other.target_protocol_addr()
    }
}

impl core::cmp::Eq for ArpPacket {}

impl core::hash::Hash for ArpPacket {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.hw_addr_type.hash(state);
        self.proto_addr_type.hash(state);
        self.hw_addr_size.hash(state);
        self.proto_addr_size.hash(state);
        self.operation.hash(state);
        self.sender_hw_addr().hash(state);
        self.sender_protocol_addr().hash(state);
        self.target_hw_addr().hash(state);
        self.target_protocol_addr().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use err::arp::ArpNewError;

    use crate::*;

    #[test]
    fn new() {
        // ok case
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[1, 2, 3],
                &[4, 5, 6, 7, 8],
                &[9, 10, 11],
                &[12, 13, 14, 15, 16],
            )
            .unwrap();
            assert_eq!(3, actual.hw_addr_size());
            assert_eq!(5, actual.proto_addr_size());
            assert_eq!(ArpHardwareId::ASH, actual.hw_addr_type);
            assert_eq!(EtherType::PROVIDER_BRIDGING, actual.proto_addr_type);
            assert_eq!(ArpOperation::REQUEST, actual.operation);
            assert_eq!(&[1, 2, 3], actual.sender_hw_addr());
            assert_eq!(&[4, 5, 6, 7, 8], actual.sender_protocol_addr());
            assert_eq!(&[9, 10, 11], actual.target_hw_addr());
            assert_eq!(&[12, 13, 14, 15, 16], actual.target_protocol_addr());
        }

        // ok case (upper hw size)
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[1; 255],
                &[4, 5, 6, 7, 8],
                &[2; 255],
                &[12, 13, 14, 15, 16],
            )
            .unwrap();
            assert_eq!(255, actual.hw_addr_size());
            assert_eq!(5, actual.proto_addr_size());
            assert_eq!(ArpHardwareId::ASH, actual.hw_addr_type);
            assert_eq!(EtherType::PROVIDER_BRIDGING, actual.proto_addr_type);
            assert_eq!(ArpOperation::REQUEST, actual.operation);
            assert_eq!(&[1; 255], actual.sender_hw_addr());
            assert_eq!(&[4, 5, 6, 7, 8], actual.sender_protocol_addr());
            assert_eq!(&[2; 255], actual.target_hw_addr());
            assert_eq!(&[12, 13, 14, 15, 16], actual.target_protocol_addr());
        }

        // ok case (protocol hw size)
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[3, 4, 5],
                &[1; 255],
                &[6, 7, 8],
                &[2; 255],
            )
            .unwrap();
            assert_eq!(3, actual.hw_addr_size());
            assert_eq!(255, actual.proto_addr_size());
            assert_eq!(ArpHardwareId::ASH, actual.hw_addr_type);
            assert_eq!(EtherType::PROVIDER_BRIDGING, actual.proto_addr_type);
            assert_eq!(ArpOperation::REQUEST, actual.operation);
            assert_eq!(&[3, 4, 5], actual.sender_hw_addr());
            assert_eq!(&[1; 255], actual.sender_protocol_addr());
            assert_eq!(&[6, 7, 8], actual.target_hw_addr());
            assert_eq!(&[2; 255], actual.target_protocol_addr());
        }

        // hw slice len differ error
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[1, 2, 3],
                &[],
                &[4, 5, 6, 7],
                &[],
            );
            assert_eq!(Err(ArpNewError::HwAddrLenInconsistent(3, 4)), actual);
        }
        // protocol slice len differ error
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[],
                &[1, 2, 3],
                &[],
                &[4, 5, 6, 7],
            );
            assert_eq!(Err(ArpNewError::ProtocolAddrLenInconsistent(3, 4)), actual);
        }

        // hardware length error
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[0; 256],
                &[1, 2, 3, 4],
                &[0; 256],
                &[5, 6, 7, 8],
            );
            assert_eq!(Err(ArpNewError::HwAddrLenTooBig(256)), actual);
        }

        // protocol length error
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[1, 2, 3, 4],
                &[0; 256],
                &[5, 6, 7, 8],
                &[0; 256],
            );
            assert_eq!(Err(ArpNewError::ProtocolAddrLenTooBig(256)), actual);
        }
    }

    #[test]
    fn new_unchecked() {
        // ok case
        {
            let actual = unsafe {
                ArpPacket::new_unchecked(
                    ArpHardwareId::ASH,
                    EtherType::PROVIDER_BRIDGING,
                    ArpOperation::REQUEST,
                    &[1, 2, 3],
                    &[4, 5, 6, 7, 8],
                    &[9, 10, 11],
                    &[12, 13, 14, 15, 16],
                )
            };
            assert_eq!(3, actual.hw_addr_size());
            assert_eq!(5, actual.proto_addr_size());
            assert_eq!(ArpHardwareId::ASH, actual.hw_addr_type);
            assert_eq!(EtherType::PROVIDER_BRIDGING, actual.proto_addr_type);
            assert_eq!(ArpOperation::REQUEST, actual.operation);
            assert_eq!(&[1, 2, 3], actual.sender_hw_addr());
            assert_eq!(&[4, 5, 6, 7, 8], actual.sender_protocol_addr());
            assert_eq!(&[9, 10, 11], actual.target_hw_addr());
            assert_eq!(&[12, 13, 14, 15, 16], actual.target_protocol_addr());
        }

        // ok case (upper hw size)
        {
            let actual = unsafe {
                ArpPacket::new_unchecked(
                    ArpHardwareId::ASH,
                    EtherType::PROVIDER_BRIDGING,
                    ArpOperation::REQUEST,
                    &[0; 255],
                    &[4, 5, 6, 7, 8],
                    &[0; 255],
                    &[12, 13, 14, 15, 16],
                )
            };
            assert_eq!(255, actual.hw_addr_size());
            assert_eq!(5, actual.proto_addr_size());
            assert_eq!(ArpHardwareId::ASH, actual.hw_addr_type);
            assert_eq!(EtherType::PROVIDER_BRIDGING, actual.proto_addr_type);
            assert_eq!(ArpOperation::REQUEST, actual.operation);
            assert_eq!(&[0; 255], actual.sender_hw_addr());
            assert_eq!(&[4, 5, 6, 7, 8], actual.sender_protocol_addr());
            assert_eq!(&[0; 255], actual.target_hw_addr());
            assert_eq!(&[12, 13, 14, 15, 16], actual.target_protocol_addr());
        }

        // ok case (protocol hw size)
        {
            let actual = ArpPacket::new(
                ArpHardwareId::ASH,
                EtherType::PROVIDER_BRIDGING,
                ArpOperation::REQUEST,
                &[1, 2, 3],
                &[0; 255],
                &[9, 10, 11],
                &[0; 255],
            )
            .unwrap();
            assert_eq!(3, actual.hw_addr_size());
            assert_eq!(255, actual.proto_addr_size());
            assert_eq!(ArpHardwareId::ASH, actual.hw_addr_type);
            assert_eq!(EtherType::PROVIDER_BRIDGING, actual.proto_addr_type);
            assert_eq!(ArpOperation::REQUEST, actual.operation);
            assert_eq!(&[1, 2, 3], actual.sender_hw_addr());
            assert_eq!(&[0; 255], actual.sender_protocol_addr());
            assert_eq!(&[9, 10, 11], actual.target_hw_addr());
            assert_eq!(&[0; 255], actual.target_protocol_addr());
        }
    }

    #[test]
    fn arp_packet_works() {
        let bytes = [
            0, 1, // hardware type
            8, 0, // proto type
            6, 4, // sizes
            0, 1, // arp operation
            0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, // src mac
            10, 10, 1, 135, // src ip
            0xde, 0xad, 0xc0, 0x00, 0xff, 0xee, // dest mac
            192, 168, 1, 253, // dest ip
        ];

        let expected = ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            ArpOperation::REQUEST,
            &[0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b],
            &[10, 10, 1, 135],
            &[0xde, 0xad, 0xc0, 0x00, 0xff, 0xee],
            &[192, 168, 1, 253],
        )
        .unwrap();

        let actual = ArpPacket::from_slice(&bytes).unwrap();

        assert_eq!(expected, actual);
    }
}
