use std::io;

/// A reader that also throws an error when a seek
/// to a non existing position is executed (not normally the behavior).
///
/// Note that this is not the default behavior of seek
/// but it is needed for testing purposes.
pub struct TestReader {
    data: Vec<u8>,
    cur_offset: usize
}

impl TestReader {
    /// Creates a reader with the given data
    pub fn new(data: &[u8]) -> TestReader {
        TestReader{
            data: {
                let mut v = Vec::with_capacity(data.len());
                v.extend_from_slice(data);
                v
            },
            cur_offset: 0
        }
    }

    /// Current offset from the start.
    pub fn cur_offset(&self) -> usize {
        self.cur_offset
    }
}

impl io::Read for TestReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() > self.data.len() - self.cur_offset {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
        } else {
            buf.clone_from_slice(
                &self.data[
                    self.cur_offset..(self.cur_offset + buf.len())
                ]
            );
            self.cur_offset += buf.len();
            Ok(buf.len())
        }
    }
}

impl io::Seek for TestReader{
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        use io::SeekFrom::*;

        let new_offset = match pos {
            Start(start_offset) => start_offset as i64,
            End(end_offset) => (self.data.len() as i64) + end_offset,
            Current(offset) => (self.cur_offset as i64) + offset,
        };

        if new_offset < 0 {
            Err(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                )
            )
        } else if new_offset > (self.data.len() as i64) {
            // Note this is not default behavior but is usefull for
            // testing. Normally a seek over the end is allowed.
            Err(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                )
            )
        } else {
            self.cur_offset = new_offset as usize;
            Ok(self.cur_offset as u64)
        }
    }
}

#[test]
fn read() {
    use io::Read;
    {
        let mut reader = TestReader::new(&[1,2,3,4]);
        {
            let mut tar: [u8;4] = [0;4];
            assert_eq!(4, reader.read(&mut tar).unwrap());
            assert_eq!(&tar[..], &[1,2,3,4]);
        }
        {
            let mut tar: [u8;1] = [0];
            assert_eq!(
                io::ErrorKind::UnexpectedEof,
                reader.read(&mut tar).unwrap_err().kind()
            );
        }
    }
}

#[test]
fn seek() {
    use io::Seek;
    use io::SeekFrom::*;
    // ok seeks
    {
        let mut reader = TestReader::new(&[1,2,3,4]);
        assert_eq!(2, reader.seek(Start(2)).unwrap());
        assert_eq!(reader.cur_offset(), 2);
        assert_eq!(3, reader.seek(Current(1)).unwrap());
        assert_eq!(3, reader.cur_offset());
        assert_eq!(1, reader.seek(End(-3)).unwrap());
        assert_eq!(1, reader.cur_offset());
    }
    // bad seeks
    {
        let mut reader = TestReader::new(&[1,2,3,4]);
        assert_eq!(
            io::ErrorKind::InvalidInput,
            reader.seek(Start(5)).unwrap_err().kind()
        );
    }
    {
        let mut reader = TestReader::new(&[1,2,3,4]);
        reader.seek(Start(2)).unwrap();
        assert_eq!(
            io::ErrorKind::InvalidInput,
            reader.seek(Current(3)).unwrap_err().kind()
        );
        assert_eq!(
            io::ErrorKind::InvalidInput,
            reader.seek(Current(-3)).unwrap_err().kind()
        );
    }
    {
        let mut reader = TestReader::new(&[1,2,3,4]);
        assert_eq!(
            io::ErrorKind::InvalidInput,
            reader.seek(End(-5)).unwrap_err().kind()
        );
        assert_eq!(
            io::ErrorKind::InvalidInput,
            reader.seek(End(1)).unwrap_err().kind()
        );
    }
}
