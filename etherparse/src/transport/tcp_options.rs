use crate::{TcpHeader, TcpOptionElement, TcpOptionWriteError, tcp_option, TcpOptionsIterator};

/// Options present in a TCP header.
/// 
/// # Examples (reading)
/// 
/// The underlying bytes can be accessed via the [`TcpOptions::as_slice`] method:
/// 
/// ```
/// use etherparse::{
///     TcpOptions,
///     tcp_option::{KIND_WINDOW_SCALE, LEN_WINDOW_SCALE, KIND_END}
/// };
/// 
/// let tcp_options = TcpOptions::from([
///     KIND_WINDOW_SCALE, LEN_WINDOW_SCALE, 2, KIND_END
/// ]);
/// 
/// // `as_slice` allows access to the raw encoded data
/// let slice = tcp_options.as_slice();
/// 
/// assert_eq!(
///     slice,
///     [KIND_WINDOW_SCALE, LEN_WINDOW_SCALE, 2, KIND_END]
/// );
/// ```
/// 
/// It also possible to iterate over the decoded [`TcpOptionElement`]s
/// by calling [`TcpOptions::elements_iter`]:
/// 
/// ```
/// use etherparse::{
///     TcpOptions,
///     TcpOptionElement::WindowScale,
///     tcp_option::{KIND_WINDOW_SCALE, LEN_WINDOW_SCALE, KIND_END}
/// };
/// 
/// let tcp_options = TcpOptions::from([
///     KIND_WINDOW_SCALE, LEN_WINDOW_SCALE, 2, KIND_END
/// ]);
/// 
/// // `elements_iter` allows iteration over the decoded elements
/// // and decoding errors
/// let mut iter = tcp_options.elements_iter();
/// 
/// assert_eq!(
///     iter.collect::<Vec<_>>(),
///     vec![Ok(WindowScale(2))]
/// );
/// ```
/// 
/// # Examples (constructing)
/// 
/// Arrays of type `[u8;4]`, `[u8;8]`, `[u8;12]`, `[u8;16]`, `[u8;20]`,
/// `[u8;24]`, `[u8;28]`, `[u8;32]`, `[u8;36]`, `[u8;40]` can directly be
/// converted with the `from` or `into` methods to [`TcpOptions`]:
/// 
/// ```
/// use etherparse::TcpOptions;
/// 
/// // static sized arrays of size 4,8,... 40 can directly be converted
/// // via `from` or `into`
/// let options: TcpOptions = [1,2,3,4].into();
///
/// assert_eq!(&options[..], &[1,2,3,4]);
/// ```
/// 
/// Slices can be converted with `try_from` or `try_into` into [`TcpOptions`].
/// If the len of 40 bytes is exceeded an error is returned and if the
/// len is not a multiple of 4 the len is automatically increased to the next
/// multiple of 4 value and the data filled up with zeroes (equivalent to the
/// TCP END option):
/// 
/// ```
/// use etherparse::TcpOptions;
/// {
///     let data = [1u8,2,3,4,5,6,7,8];
/// 
///     // slices can be converted into TcpOptions via `try_from` or `try_into`
///     let options: TcpOptions = (&data[..]).try_into().unwrap();
/// 
///     assert_eq!(options.as_slice(), &data);
/// }
/// {
///     let data = [1u8];
/// 
///     // len is automatically increased to a multiple of 4 (filled
///     // with 0, also known as the END TCP option).
///     let options = TcpOptions::try_from(&data[..]).unwrap();
/// 
///     assert_eq!(options.as_slice(), &[1, 0, 0, 0]);
/// }
/// {
///     use etherparse::TcpOptionWriteError::NotEnoughSpace;
/// 
///     let data = [0u8;41]; // 41 bytes
/// 
///     // slices with a len bigger then 40 cause an error
///     let result = TcpOptions::try_from(&data[..]);
///     assert_eq!(result, Err(NotEnoughSpace(41)));
/// }
/// ```
/// 
/// Slices containing [`TcpOptionElement`]s can also be converted via
/// `try_from` or `try_into` as long as the encoded elements are within
/// 40 bytes:
/// 
/// ```
/// use etherparse::{
///     TcpOptions,
///     tcp_option::{KIND_WINDOW_SCALE, LEN_WINDOW_SCALE, KIND_NOOP, KIND_END},
///     TcpOptionElement::{Noop, WindowScale}
/// };
///
/// let elements = [WindowScale(123), Noop, Noop];
/// 
/// // try_from encodes the options into the "on the wire" format
/// let options = TcpOptions::try_from(&elements[..]).unwrap();
/// 
/// assert_eq!(
///     options.as_slice(),
///     &[
///         KIND_WINDOW_SCALE, LEN_WINDOW_SCALE, 123, KIND_NOOP,
///         KIND_NOOP, KIND_END, KIND_END, KIND_END
///     ]
/// );
/// ```
#[derive(Clone)]
pub struct TcpOptions {
    /// Number of bytes in the buffer.
    pub(crate) len: u8,
    
    /// Buffer containing the options of the header
    /// (note that the `len` field defines the actual length). Use
    /// the options() method if you want to get a slice that has
    /// the actual length of the options.
    pub(crate) buf: [u8; 40],
}

impl TcpOptions {

    /// Maximum number of bytes that can be part of an TCP options.
    pub const MAX_LEN: usize = 40;

    /// Tries to convert an `u8` slice into [`TcpOptions`].
    pub fn try_from_slice(slice: &[u8]) -> Result<TcpOptions, TcpOptionWriteError> {

        // check length
        if Self::MAX_LEN < slice.len() {
            Err(TcpOptionWriteError::NotEnoughSpace(slice.len()))
        } else {
            let len = slice.len() as u8;

            // reset all to zero to ensure padding
            Ok(TcpOptions{
                len: ((len >> 2) << 2) + if 0 != len & 0b11 {
                    // NOTE: If the slice length is not a multiple of
                    // 4 the length is automatically increased to be
                    // a multiple of 4 and the data is filled up with
                    // zeroes.
                    4
                } else {
                    0
                },
                buf: {
                    let mut buf = [0;40];
                    buf[..slice.len()].copy_from_slice(slice);
                    buf
                },
            })
        }
    }

    /// Tries to convert [`crate::TcpOptionElement`] into serialized
    /// form as [`TcpOptions`].
    pub fn try_from_elements(elements: &[TcpOptionElement]) -> Result<TcpOptions, TcpOptionWriteError> {
        // calculate the required size of the options
        use crate::TcpOptionElement::*;
        let required_len = elements.iter().fold(0, |acc, ref x| {
            acc + match x {
                Noop => 1,
                MaximumSegmentSize(_) => 4,
                WindowScale(_) => 3,
                SelectiveAcknowledgementPermitted => 2,
                SelectiveAcknowledgement(_, rest) => rest.iter().fold(10, |acc2, ref y| match y {
                    None => acc2,
                    Some(_) => acc2 + 8,
                }),
                Timestamp(_, _) => 10,
            }
        });

        if Self::MAX_LEN < required_len {
            Err(TcpOptionWriteError::NotEnoughSpace(required_len))
        } else {
            // reset the options to null
            let mut buf = [0u8;TcpOptions::MAX_LEN];
            let mut len: usize = 0;

            // write the options to the buffer
            use tcp_option::*;
            for element in elements {
                match element {
                    Noop => {
                        buf[len] = KIND_NOOP;
                        len += 1;
                    }
                    MaximumSegmentSize(value) => {
                        // determine insertion area
                        let t = &mut buf[len .. len + 4];

                        // insert data
                        let value = value.to_be_bytes();
                        t[0] = KIND_MAXIMUM_SEGMENT_SIZE;
                        t[1] = 4;
                        t[2] = value[0];
                        t[3] = value[1];

                        len += 4;
                    }
                    WindowScale(value) => {
                        // determine insertion area
                        let t = &mut buf[len..len + 3];
                        
                        // write data
                        t[0] = KIND_WINDOW_SCALE;
                        t[1] = 3;
                        t[2] = *value;

                        len += 3;
                    }
                    SelectiveAcknowledgementPermitted => {
                        // determine insertion area
                        let insert = &mut buf[len..len + 2];

                        // write data
                        insert[0] = KIND_SELECTIVE_ACK_PERMITTED;
                        insert[1] = 2;

                        len += 2;
                    }
                    SelectiveAcknowledgement(first, rest) => {
                        //write guranteed data
                        {
                            let t = &mut buf[len..len + 10];
                            len += 10;

                            t[0] = KIND_SELECTIVE_ACK;
                            //write the length
                            t[1] = rest.iter().fold(10, |acc, ref y| match y {
                                None => acc,
                                Some(_) => acc + 8,
                            });
                            // write first
                            t[2..6].copy_from_slice(&first.0.to_be_bytes());
                            t[6..10].copy_from_slice(&first.1.to_be_bytes());
                        }
                        //write the rest
                        for v in rest {
                            match v {
                                None => {}
                                Some((a, b)) => {
                                    // determine insertion area
                                    let t = &mut buf[len..len + 8];

                                    // insert
                                    t[0..4].copy_from_slice(&a.to_be_bytes());
                                    t[4..8].copy_from_slice(&b.to_be_bytes());

                                    len += 8;
                                }
                            }
                        }
                    }
                    Timestamp(a, b) => {
                        let t = &mut buf[len..len + 10];

                        t[0] = KIND_TIMESTAMP;
                        t[1] = 10;
                        t[2..6].copy_from_slice(&a.to_be_bytes());
                        t[6..10].copy_from_slice(&b.to_be_bytes());

                        len += 10;
                    }
                }
            }
            // set the new data offset
            if len > 0 {
                if 0 != len & 0b11 {
                    len = (len & (!0b11)) + 4;
                }
            }
            // done
            Ok(TcpOptions{
                len: len as u8,
                buf,
            })
        }
    }

    /// The number of 32 bit words in the TCP Header.
    ///
    /// This indicates where the data begins.  The TCP header (even one
    /// including options) is an integral number of 32 bits long.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        TcpHeader::MIN_DATA_OFFSET + (self.len >> 2)
    }

    /// Number of bytes in the buffer as an unsigned 8 bit integer.
    #[inline]
    pub fn len_u8(&self) -> u8 {
        self.len
    }

    /// Number of bytes in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Slice containing the options.
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        debug_assert!(self.len <= 40);
        // SAFETY: Safe as all constructing methods verify len to be less then 40.
        unsafe {
            core::slice::from_raw_parts(self.buf.as_ptr(), self.len())
        }
    }

    /// Mutable slice containing the options.
    #[inline]
    pub fn as_mut_slice<'a>(&'a mut self) -> &'a mut [u8] {
        debug_assert!(self.len <= 40);
        // SAFETY: Safe as all constructing methods verify len to be less then 40.
        unsafe {
            core::slice::from_raw_parts_mut(self.buf.as_mut_ptr(), self.len())
        }
    }

    /// Returns an iterator that allows to iterate through the
    /// decoded option elements.
    #[inline]
    pub fn elements_iter(&self) -> TcpOptionsIterator {
        TcpOptionsIterator {
            options: self.as_slice(),
        }
    }
}

impl Default for TcpOptions {
    #[inline]
    fn default() -> Self {
        Self {
            len: 0,
            buf: [0; 40]
        }
    }
}

impl core::cmp::Eq for TcpOptions {}
impl PartialEq for TcpOptions {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<'a> TryFrom<&'a [u8]> for TcpOptions {
    type Error = TcpOptionWriteError;

    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        TcpOptions::try_from_slice(value)
    }
}

impl<'a> TryFrom<&'a [TcpOptionElement]> for TcpOptions {
    type Error = TcpOptionWriteError;

    #[inline]
    fn try_from(value: &'a [TcpOptionElement]) -> Result<Self, Self::Error> {
        TcpOptions::try_from_elements(value)
    }
}

impl core::fmt::Debug for TcpOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.elements_iter().fmt(f)
    }
}

impl core::hash::Hash for TcpOptions {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl core::cmp::PartialOrd for TcpOptions {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.as_slice().partial_cmp(other.as_slice())
    }
}

impl core::cmp::Ord for TcpOptions {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl core::ops::Deref for TcpOptions {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<TcpOptions> for TcpOptions {
    #[inline]
    fn as_mut(&mut self) -> &mut TcpOptions {
        self
    }
}

impl AsRef<[u8]> for TcpOptions {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for TcpOptions {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

macro_rules! from_static_array {
    ($x:expr) => {
        impl From<[u8; $x]> for TcpOptions {
            #[inline]
            fn from(values: [u8; $x]) -> Self {
                let mut result = TcpOptions {
                    len: $x,
                    buf: [0; 40],
                };
                let r = result.buf.as_mut_ptr() as *mut [u8; $x];
                unsafe {
                    *r = values;
                }
                result
            }
        }
    };
}

from_static_array!(4);
from_static_array!(8);
from_static_array!(12);
from_static_array!(16);
from_static_array!(20);
from_static_array!(24);
from_static_array!(28);
from_static_array!(32);
from_static_array!(36);

/*
#[cfg(test)]
mod test {
    use super::TcpOptions;

    #[test]
    fn try_from_slice() {
        todo!()
    }

    #[test]
    fn try_from_elements() {
        todo!()
    }

    #[test]
    fn as_slice() {
        todo!()
    }

    #[test]
    fn as_mut_slice() {
        todo!()
    }

    #[test]
    fn options_iterator() {
        todo!()
    }

    #[test]
    fn default() {
        let actual: TcpOptions = Default::default();
        assert_eq!(0, actual.len);
        assert_eq!([0u8;40], actual.buf);
    }

    #[test]
    fn eq() {
        todo!()
    }

    #[test]
    fn try_from() {
        todo!()
    }

    #[test]
    fn debug_fmt() {
        todo!()
    }

    #[test]
    fn clone_eq_hash_ord() {
        todo!()
    }

    #[test]
    fn deref() {
        todo!()
    }

    #[test]
    fn as_ref() {
        todo!()
    }

    #[test]
    fn as_mut() {
        todo!()
    }

    #[test]
    fn from() {
        todo!()
    }
}
 */