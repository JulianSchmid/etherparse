use crate::err::{LenSource, io::LimitedReadError, LenError, Layer};

/// Helper Reader that returns an io error as soon as
/// the maximum read len is read.
#[cfg(feature = "std")]
pub struct LimitedReader<'a, T> {
    reader: &'a mut T,
    /// Maximum len that is allowed to be read.
    max_len: usize,
    /// Source of the maximum length.
    len_source: LenSource,
    layer: Layer,
    layer_offset: usize,
    /// Len that was read since the creation of this reader.
    read_len: usize,
}

#[cfg(feature = "std")]
impl<'a, T: std::io::Read + Sized> LimitedReader<'a, T> {
    /// Setup a new limited reader.
    pub fn new(reader: &'a mut T, max_len: usize, len_source: LenSource, layer_offset: usize, layer: Layer) -> LimitedReader<'a, T> {
        LimitedReader{
            reader,
            max_len,
            len_source,
            layer,
            layer_offset,
            read_len: 0,
        }
    }

    /// Set currrent position as starting position for a layer.
    pub fn start_layer(&mut self, layer: Layer) {
        self.layer_offset += self.read_len;
        self.max_len -= self.read_len;
        self.read_len = 0;
        self.layer = layer;
    }

    /// Try read the given buf length from the reader.
    /// 
    /// Triggers an len error if the 
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), LimitedReadError> {
        use LimitedReadError::*;
        if self.max_len - self.read_len < buf.len() {
            Err(Len(LenError{
                required_len: self.read_len + buf.len(),
                len: self.max_len,
                len_source: self.len_source,
                layer: self.layer,
                layer_start_offset: self.layer_offset,
            }))
        } else {
            self.reader.read_exact(buf).map_err(Io)?;
            self.read_len += buf.len();
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {



}