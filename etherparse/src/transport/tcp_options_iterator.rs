use crate::*;

/// Allows iterating over the options after a TCP header.
#[derive(Clone, Eq, PartialEq)]
pub struct TcpOptionsIterator<'a> {
    pub(crate) options: &'a [u8],
}

impl<'a> TcpOptionsIterator<'a> {
    /// Creates an options iterator from a slice containing encoded tcp options.
    pub fn from_slice(options: &'a [u8]) -> TcpOptionsIterator<'a> {
        TcpOptionsIterator { options }
    }

    /// Returns the non processed part of the options slice.
    pub fn rest(&self) -> &'a [u8] {
        self.options
    }
}

impl<'a> Iterator for TcpOptionsIterator<'a> {
    type Item = Result<TcpOptionElement, TcpOptionReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        use crate::TcpOptionElement::*;
        use crate::TcpOptionReadError::*;

        let expect_specific_size =
            |expected_size: u8, slice: &[u8]| -> Result<(), TcpOptionReadError> {
                let id = slice[0];
                if slice.len() < expected_size as usize {
                    Err(UnexpectedEndOfSlice {
                        option_id: id,
                        expected_len: expected_size,
                        actual_len: slice.len(),
                    })
                } else if slice[1] != expected_size {
                    Err(UnexpectedSize {
                        option_id: slice[0],
                        size: slice[1],
                    })
                } else {
                    Ok(())
                }
            };

        if self.options.is_empty() {
            None
        } else {
            //first determine the result
            use tcp_option::*;
            let result = match self.options[0] {
                //end
                KIND_END => None,
                KIND_NOOP => {
                    self.options = &self.options[1..];
                    Some(Ok(Noop))
                }
                KIND_MAXIMUM_SEGMENT_SIZE => {
                    match expect_specific_size(LEN_MAXIMUM_SEGMENT_SIZE, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            // SAFETY:
                            // Safe as the slice size is checked beforehand to be at
                            // least of size LEN_MAXIMUM_SEGMENT_SIZE (4).
                            let value =
                                unsafe { get_unchecked_be_u16(self.options.as_ptr().add(2)) };
                            self.options = &self.options[4..];
                            Some(Ok(MaximumSegmentSize(value)))
                        }
                    }
                }
                KIND_WINDOW_SCALE => match expect_specific_size(LEN_WINDOW_SCALE, self.options) {
                    Err(value) => Some(Err(value)),
                    _ => {
                        let value = self.options[2];
                        self.options = &self.options[3..];
                        Some(Ok(WindowScale(value)))
                    }
                },
                KIND_SELECTIVE_ACK_PERMITTED => {
                    match expect_specific_size(LEN_SELECTIVE_ACK_PERMITTED, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            self.options = &self.options[2..];
                            Some(Ok(SelectiveAcknowledgementPermitted))
                        }
                    }
                }
                KIND_SELECTIVE_ACK => {
                    //check that the length field can be read
                    if self.options.len() < 2 {
                        Some(Err(UnexpectedEndOfSlice {
                            option_id: self.options[0],
                            expected_len: 2,
                            actual_len: self.options.len(),
                        }))
                    } else {
                        //check that the length is an allowed one for this option
                        let len = self.options[1];
                        if len != 10 && len != 18 && len != 26 && len != 34 {
                            Some(Err(UnexpectedSize {
                                option_id: self.options[0],
                                size: len,
                            }))
                        } else if self.options.len() < (len as usize) {
                            Some(Err(UnexpectedEndOfSlice {
                                option_id: self.options[0],
                                expected_len: len,
                                actual_len: self.options.len(),
                            }))
                        } else {
                            let mut acks: [Option<(u32, u32)>; 3] = [None; 3];
                            // SAFETY:
                            // This is safe as above the len is checked
                            // to be at least 10 and the slice len is
                            // checked to be at least len bytes.
                            let first = unsafe {
                                (
                                    get_unchecked_be_u32(self.options.as_ptr().add(2)),
                                    get_unchecked_be_u32(self.options.as_ptr().add(6)),
                                )
                            };
                            for (i, item) in acks.iter_mut().enumerate().take(3) {
                                let offset = 2 + 8 + (i * 8);
                                // SAFETY:
                                // len can only be 10, 18, 26 or 34
                                // therefore if the offset is smaller then the
                                // len, then at least 8 bytes can be read.
                                unsafe {
                                    if offset < (len as usize) {
                                        *item = Some((
                                            get_unchecked_be_u32(self.options.as_ptr().add(offset)),
                                            get_unchecked_be_u32(
                                                self.options.as_ptr().add(offset + 4),
                                            ),
                                        ));
                                    }
                                }
                            }
                            //iterate the options
                            self.options = &self.options[len as usize..];
                            Some(Ok(SelectiveAcknowledgement(first, acks)))
                        }
                    }
                }
                KIND_TIMESTAMP => {
                    match expect_specific_size(LEN_TIMESTAMP, self.options) {
                        Err(value) => Some(Err(value)),

                        _ => unsafe {
                            let t = Timestamp(
                                // SAFETY:
                                // Safe as the len first gets checked to be equal
                                // LEN_TIMESTAMP (10).
                                get_unchecked_be_u32(self.options.as_ptr().add(2)),
                                get_unchecked_be_u32(self.options.as_ptr().add(6)),
                            );
                            self.options = &self.options[10..];
                            Some(Ok(t))
                        },
                    }
                }

                //unknown id
                _ => Some(Err(UnknownId(self.options[0]))),
            };

            //in case the result was an error or the end move the slice to an end position
            match result {
                None | Some(Err(_)) => {
                    let len = self.options.len();
                    self.options = &self.options[len..len];
                }
                _ => {}
            }

            //finally return the result
            result
        }
    }
}

impl<'a> core::fmt::Debug for TcpOptionsIterator<'a> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        let mut list = fmt.debug_list();

        // create a copy and iterate over all elements
        for it in self.clone() {
            match it {
                Ok(e) => {
                    list.entry(&e);
                }
                Err(e) => {
                    list.entry(&Result::<(), TcpOptionReadError>::Err(e.clone()));
                }
            }
        }

        list.finish()
    }
}
