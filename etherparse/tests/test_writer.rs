use std::io;

/// Writer that can be configured to returns an error on write if
/// more then the specified maximum size has been written.
///
/// This writer is used in the tests to check if
/// writing code correctly early returns if a write
/// triggers an error.
pub struct TestWriter {
    data: Vec<u8>,
    cur_size: usize,
    max_size: Option<usize>,
    error_kind: io::ErrorKind,
}

impl TestWriter {

    /// Create a new test writer without a maximum size
    pub fn new() -> TestWriter {
        TestWriter{
            data: Vec::new(),
            cur_size: 0,
            max_size: None,
            error_kind: io::ErrorKind::UnexpectedEof,
        }
    }

    /// Create a new error writer that throws an `io::Error` of kind `io::Error::UnexpectedEof` 
    /// if a write would exceed the given maximum size.
    pub fn with_max_size(max_size: usize) -> TestWriter {
        TestWriter{
            data: Vec::new(),
            cur_size: 0,
            max_size: Some(max_size),
            error_kind: io::ErrorKind::UnexpectedEof,
        }
    }

    /// Create a new error writer that throws an `io::Error` of the given kind
    /// if a write would exceed the given maximum size.
    pub fn with_max_size_and_error_kind(max_size: usize, error_kind: io::ErrorKind) -> TestWriter {
        TestWriter{
            data: Vec::new(),
            cur_size: 0,
            max_size: Some(max_size),
            error_kind,
        }
    }

    /// The error kind produced if the size is exceeded
    pub fn error_kind(&self) -> io::ErrorKind {
        self.error_kind
    }
}

impl io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.cur_size += buf.len();
        if let Some(max_size) = self.max_size {
            if self.cur_size > max_size {
                Err(io::Error::new(self.error_kind, "Maximum size exceeded"))
            } else {
                Ok(buf.len())
            }
        } else {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn new() {
    use io::Write;

    let mut writer = TestWriter::new();
    assert_eq!(true, writer.flush().is_ok());
    assert_eq!(4, writer.write(&[1,2,3,4]).unwrap());
}

#[test]
fn with_max_size() {
    use io::Write;

    let mut writer = TestWriter::with_max_size(6);
    // write within bounds
    assert_eq!(true, writer.flush().is_ok());
    assert_eq!(4, writer.write(&[1,2,3,4]).unwrap());
    assert_eq!(true, writer.flush().is_ok());
    // on bounds on border
    assert_eq!(2, writer.write(&[1,2]).unwrap());
    // outside of bounds
    assert_eq!(io::ErrorKind::UnexpectedEof, writer.write(&[1]).unwrap_err().kind());
    assert_eq!(true, writer.flush().is_ok());
}

#[test]
fn new_with_error_kind() {
    use io::Write;

    let mut writer = TestWriter::with_max_size_and_error_kind(3, io::ErrorKind::Other);
    // write within bounds
    assert_eq!(1, writer.write(&[1]).unwrap());
    // outside of bounds
    assert_eq!(io::ErrorKind::Other, writer.write(&[1,2,3]).unwrap_err().kind());
}